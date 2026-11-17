//! SOCKS5 method negotiation and RFC 1929 username/password authentication.

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::proto::{
    AUTH_FAILURE, AUTH_SUCCESS, METHOD_NO_ACCEPTABLE, METHOD_NO_AUTH, METHOD_USERPASS,
    USERPASS_VERSION, VERSION,
};
use crate::{Error, Result};

/// A username/password pair used for SOCKS5 USERNAME/PASSWORD authentication.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Credential {
    /// The username (at most 255 bytes on the wire).
    pub username: String,
    /// The password (at most 255 bytes on the wire).
    pub password: String,
}

impl Credential {
    /// Creates a new credential.
    pub fn new(username: impl Into<String>, password: impl Into<String>) -> Self {
        Self {
            username: username.into(),
            password: password.into(),
        }
    }
}

fn io_invalid(message: &'static str) -> Error {
    Error::Io(std::io::Error::new(
        std::io::ErrorKind::InvalidData,
        message,
    ))
}

/// Compares two byte strings without early exit so the comparison time does
/// not reveal the position of the first differing byte.
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    let len = a.len().max(b.len());
    let mut diff = 0u8;
    for i in 0..len {
        diff |= a.get(i).copied().unwrap_or(0) ^ b.get(i).copied().unwrap_or(0);
    }
    diff == 0 && a.len() == b.len()
}

/// Performs server-side authentication and returns the authenticated username
/// (an empty string when NO_AUTH was selected).
pub async fn authenticate<S>(stream: &mut S, credentials: &[Credential]) -> Result<String>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut head = [0u8; 2];
    stream.read_exact(&mut head).await?;
    let version = head[0];
    let method_count = head[1] as usize;
    if version != VERSION {
        return Err(Error::UnsupportedVersion(version));
    }
    if method_count == 0 {
        return Err(io_invalid("SOCKS5 greeting contains zero methods"));
    }

    let mut methods = vec![0u8; method_count];
    stream.read_exact(&mut methods).await?;
    let wants_no_auth = methods.contains(&METHOD_NO_AUTH);
    let wants_userpass = methods.contains(&METHOD_USERPASS);

    if !wants_no_auth && !wants_userpass {
        stream.write_all(&[VERSION, METHOD_NO_ACCEPTABLE]).await?;
        stream.flush().await?;
        return Err(Error::NoAcceptableMethod);
    }

    if wants_no_auth && credentials.is_empty() {
        stream.write_all(&[VERSION, METHOD_NO_AUTH]).await?;
        stream.flush().await?;
        return Ok(String::new());
    }

    if wants_userpass {
        if credentials.is_empty() {
            return Err(Error::AuthenticationFailed);
        }
        stream.write_all(&[VERSION, METHOD_USERPASS]).await?;
        stream.flush().await?;

        let mut sub = [0u8; 2];
        stream.read_exact(&mut sub).await?;
        if sub[0] != USERPASS_VERSION {
            return Err(io_invalid(
                "unsupported username/password sub-negotiation version",
            ));
        }

        let mut user = vec![0u8; sub[1] as usize];
        stream.read_exact(&mut user).await?;
        let mut len = [0u8; 1];
        stream.read_exact(&mut len).await?;
        let mut password = vec![0u8; len[0] as usize];
        stream.read_exact(&mut password).await?;

        // Walk every configured credential without short-circuiting so the
        // response time does not reveal which credential matched (or where in
        // the list it lives).
        let mut authenticated = false;
        for credential in credentials {
            let user_match = constant_time_eq(credential.username.as_bytes(), &user);
            let password_match = constant_time_eq(credential.password.as_bytes(), &password);
            authenticated |= user_match && password_match;
        }

        if authenticated {
            stream.write_all(&[USERPASS_VERSION, AUTH_SUCCESS]).await?;
            stream.flush().await?;
            let name = String::from_utf8_lossy(&user).into_owned();
            return Ok(name);
        }

        stream.write_all(&[USERPASS_VERSION, AUTH_FAILURE]).await?;
        stream.flush().await?;
        return Err(Error::AuthenticationFailed);
    }

    // The client only offered NO_AUTH, but the server has credentials.
    Err(Error::AuthenticationFailed)
}

/// Performs the client half of method negotiation for an egress SOCKS5 proxy.
/// Used by the PROXY egress action.
pub async fn client_handshake<S>(stream: &mut S, credential: Option<&Credential>) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let method = if credential.is_some() {
        METHOD_USERPASS
    } else {
        METHOD_NO_AUTH
    };
    stream.write_all(&[VERSION, 1, method]).await?;
    stream.flush().await?;

    let mut resp = [0u8; 2];
    stream.read_exact(&mut resp).await?;
    if resp[0] != VERSION || resp[1] != method {
        return Err(Error::NoAcceptableMethod);
    }

    let Some(credential) = credential else {
        return Ok(());
    };

    let user = credential.username.as_bytes();
    let password = credential.password.as_bytes();
    if user.len() > 255 || password.len() > 255 {
        return Err(io_invalid("SOCKS5 username or password exceeds 255 bytes"));
    }

    let mut request = Vec::with_capacity(user.len() + password.len() + 3);
    request.push(USERPASS_VERSION);
    request.push(user.len() as u8);
    request.extend_from_slice(user);
    request.push(password.len() as u8);
    request.extend_from_slice(password);
    stream.write_all(&request).await?;
    stream.flush().await?;

    let mut auth_resp = [0u8; 2];
    stream.read_exact(&mut auth_resp).await?;
    if auth_resp[0] != USERPASS_VERSION || auth_resp[1] != AUTH_SUCCESS {
        return Err(Error::AuthenticationFailed);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::duplex;

    fn greeting(methods: &[u8]) -> Vec<u8> {
        let mut g = vec![VERSION, methods.len() as u8];
        g.extend_from_slice(methods);
        g
    }

    #[tokio::test]
    async fn no_auth_when_no_credentials_configured() {
        let (mut client, mut server) = duplex(1024);
        client
            .write_all(&greeting(&[METHOD_NO_AUTH]))
            .await
            .unwrap();
        let user = authenticate(&mut server, &[]).await.unwrap();
        assert!(user.is_empty());
        let mut resp = [0u8; 2];
        client.read_exact(&mut resp).await.unwrap();
        assert_eq!(resp, [VERSION, METHOD_NO_AUTH]);
    }

    #[tokio::test]
    async fn userpass_success_and_failure() {
        let creds = vec![
            Credential::new("alice", "secret"),
            Credential::new("bob", "pw"),
        ];
        for (user, pass, ok) in [
            ("alice", "secret", true),
            ("bob", "pw", true),
            ("alice", "wrong", false),
            ("mallory", "secret", false),
        ] {
            let (mut client, mut server) = duplex(1024);
            client
                .write_all(&greeting(&[METHOD_NO_AUTH, METHOD_USERPASS]))
                .await
                .unwrap();
            let credentials = creds.clone();
            let server_task =
                tokio::spawn(async move { authenticate(&mut server, &credentials).await });

            let mut method = [0u8; 2];
            client.read_exact(&mut method).await.unwrap();
            assert_eq!(method, [VERSION, METHOD_USERPASS]);
            let mut body = vec![USERPASS_VERSION, user.len() as u8];
            body.extend_from_slice(user.as_bytes());
            body.push(pass.len() as u8);
            body.extend_from_slice(pass.as_bytes());
            client.write_all(&body).await.unwrap();
            let mut result = [0u8; 2];
            client.read_exact(&mut result).await.unwrap();
            if ok {
                assert_eq!(result, [USERPASS_VERSION, AUTH_SUCCESS]);
                assert_eq!(server_task.await.unwrap().unwrap(), user);
            } else {
                assert_eq!(result, [USERPASS_VERSION, AUTH_FAILURE]);
                assert!(server_task.await.unwrap().is_err());
            }
        }
    }

    #[tokio::test]
    async fn unsupported_methods_get_no_acceptable() {
        let (mut client, mut server) = duplex(1024);
        client.write_all(&greeting(&[0x7f])).await.unwrap();
        assert!(authenticate(&mut server, &[]).await.is_err());
        let mut resp = [0u8; 2];
        client.read_exact(&mut resp).await.unwrap();
        assert_eq!(resp, [VERSION, METHOD_NO_ACCEPTABLE]);
    }

    #[tokio::test]
    async fn no_auth_rejected_when_credentials_required() {
        let (mut client, mut server) = duplex(1024);
        client
            .write_all(&greeting(&[METHOD_NO_AUTH]))
            .await
            .unwrap();
        let creds = vec![Credential::new("alice", "secret")];
        assert!(authenticate(&mut server, &creds).await.is_err());
    }
}
