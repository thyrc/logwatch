use std::io;

use futures_util::StreamExt;
use inotify::{EventMask, Inotify, WatchMask};
use std::ffi::{OsStr, OsString};
use std::fs::{self, File};
use std::io::{BufRead, BufReader, Seek, SeekFrom};
use std::path::Path;
use std::time::{Duration, Instant};

struct Watched<'a> {
    path: &'a Path,
    file: &'a OsStr,
    dir: &'a Path,
    pos: u64,
}

impl<'a> Watched<'a> {
    fn new<P: AsRef<Path> + ?Sized>(f: &'a P) -> Self {
        Watched {
            path: f.as_ref(),
            file: f.as_ref().file_name().unwrap_or_else(|| OsStr::new("")),
            dir: f.as_ref().parent().unwrap_or_else(|| Path::new("/")),
            pos: 0,
        }
    }

    fn set_pos(&mut self, n: u64) {
        self.pos = n;
    }
}

#[derive(Debug)]
enum Auth {
    Sudo,
    System,
}

#[derive(Debug)]
struct FailureMap {
    auth_type: Auth,
    auth_time: Vec<Instant>,
}

impl FailureMap {
    fn new(a: Auth) -> Self {
        FailureMap {
            auth_type: a,
            auth_time: vec![],
        }
    }

    fn add(&mut self) {
        self.auth_time.push(Instant::now());
    }
}

struct AuthFailure {
    kind: Auth,
    message: String,
}

#[tokio::main]
async fn main() -> Result<(), io::Error> {
    let mut watch = Watched::new("/var/log/auth.log");

    if watch.path.is_file() {
        let meta = fs::metadata(&watch.path)?;
        watch.set_pos(meta.len());
    }

    let sudo_failure = AuthFailure {
        kind: Auth::Sudo,
        message: String::from("pam_unix(sudo:auth): authentication failure;"),
    };
    let systemauth_failure = AuthFailure {
        kind: Auth::System,
        message: String::from("pam_unix(system-auth:auth): authentication failure;"),
    };

    let mut sudo_map = FailureMap::new(sudo_failure.kind);
    let mut system_map = FailureMap::new(systemauth_failure.kind);

    let mut inotify = Inotify::init().expect("Failed to initialize inotify");

    inotify.add_watch(&watch.dir, WatchMask::CREATE | WatchMask::MOVED_FROM)?;

    let mut file_watch =
        inotify.add_watch(&watch.path, WatchMask::MODIFY | WatchMask::MOVE_SELF)?;

    let mut buffer = [0; 32];
    let mut stream = inotify.event_stream(&mut buffer)?;

    let mut linebuffer = vec![];

    while let Some(event_or_error) = stream.next().await {
        if let Ok(event) = event_or_error {
            if Some(OsString::from(watch.file)) == event.name {
                // directory events
                if event.mask.contains(EventMask::MOVED_FROM) {
                    // println!("event: {:?}", event);
                } else if event.mask.contains(EventMask::CREATE) {
                    // println!("event: {:?}", event);
                    inotify.rm_watch(file_watch)?;
                    watch.set_pos(0);

                    file_watch =
                        inotify.add_watch(&watch.path, WatchMask::MODIFY | WatchMask::MOVE_SELF)?;
                }
            } else {
                // file events
                if event.mask.contains(EventMask::MOVE_SELF) {
                } else {
                    // println!("event: {:?}", event);
                    let metadata = fs::metadata(&watch.path)?;
                    let f = File::open(&watch.path)?;
                    let mut reader = BufReader::new(f);
                    let _pos = reader.seek(SeekFrom::Start(watch.pos))?;

                    loop {
                        linebuffer.clear();
                        let bytes_read = reader.read_until(b'\n', &mut linebuffer)?;
                        if let 0 = bytes_read {
                            break;
                        } else {
                            if String::from_utf8_lossy(&linebuffer[..])
                                .contains(&sudo_failure.message)
                            {
                                sudo_map.add();
                                if sudo_map.auth_time.len() >= 3 {
                                    println!("sudo bashing detected");
                                    sudo_map.auth_time = vec![];
                                }
                            }
                            if String::from_utf8_lossy(&linebuffer[..])
                                .contains(&systemauth_failure.message)
                            {
                                system_map.add();
                                if system_map.auth_time.len() >= 3 {
                                    println!("system-auth bashing detected");
                                    system_map.auth_time = vec![];
                                }
                            }
                        }
                    }
                    watch.set_pos(metadata.len());

                    // clean-up
                    sudo_map.auth_time = sudo_map
                        .auth_time
                        .into_iter()
                        .filter(|x| x.elapsed() <= Duration::from_secs(300))
                        .collect::<Vec<_>>();

                    system_map.auth_time = system_map
                        .auth_time
                        .into_iter()
                        .filter(|x| x.elapsed() <= Duration::from_secs(300))
                        .collect::<Vec<_>>();
                }
            }
        }
    }

    Ok(())
}
