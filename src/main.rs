use inotify::{EventMask, Inotify, WatchMask};
use std::ffi::OsStr;
use std::fs::{self, File};
use std::io::{self, BufRead, BufReader, Seek, SeekFrom};
use std::path::Path;
use std::time::{Duration, Instant};

const TIME_LIMIT: u64 = 300;
const RATE_LIMIT: usize = 3;

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
struct AuthFailure<'a> {
    kind: Auth,
    message: &'a str,
    notify: &'a str,
}

#[derive(Debug)]
struct FailureMap<'a> {
    auth_failure: AuthFailure<'a>,
    auth_failure_time: Vec<Instant>,
    notify_time: Option<Instant>,
}

impl<'a> FailureMap<'a> {
    fn new(failure: AuthFailure<'a>) -> Self {
        FailureMap {
            auth_failure: failure,
            auth_failure_time: vec![],
            notify_time: None,
        }
    }

    fn add(&mut self) {
        self.auth_failure_time.push(Instant::now());
    }

    fn clean(&mut self) {
        self.auth_failure_time
            .retain(|x| x.elapsed() <= Duration::from_secs(TIME_LIMIT));
    }
}

fn notify(fm: &mut FailureMap) -> Result<(), io::Error> {
    fm.clean();
    fm.add();
    if fm.auth_failure_time.len() >= RATE_LIMIT {
        if let Some(t) = fm.notify_time {
            if t.elapsed() >= Duration::from_secs(TIME_LIMIT) {
                println!("{}", fm.auth_failure.notify);
                fm.notify_time = fm.auth_failure_time.pop();
                fm.auth_failure_time = vec![];
            }
        } else {
            println!("{}", fm.auth_failure.notify);
            fm.notify_time = fm.auth_failure_time.pop();
            fm.auth_failure_time = vec![];
        }
    }

    Ok(())
}

fn main() -> Result<(), io::Error> {
    let mut watch = Watched::new("/var/log/auth.log");

    let mut inotify = Inotify::init().expect("Failed to initialize inotify");

    inotify.add_watch(&watch.dir, WatchMask::CREATE | WatchMask::MOVED_FROM)?;

    if watch.path.is_file() {
        let meta = fs::metadata(&watch.path)?;
        watch.set_pos(meta.len());
        inotify.add_watch(&watch.path, WatchMask::MODIFY | WatchMask::MOVE_SELF)?;
    }

    let sudo_failure = AuthFailure {
        kind: Auth::Sudo,
        message: "pam_unix(sudo:auth): authentication failure;",
        notify: "sudo bashing detected",
    };
    let systemauth_failure = AuthFailure {
        kind: Auth::System,
        message: "pam_unix(system-auth:auth): authentication failure;",
        notify: "system-auth bashing detected",
    };

    let mut sudo_map = FailureMap::new(sudo_failure);
    let mut system_map = FailureMap::new(systemauth_failure);

    let mut failures = vec![&mut sudo_map, &mut system_map];

    let mut linebuffer = vec![];

    let mut buffer = [0_u8; 4096];

    loop {
        let events = inotify.read_events_blocking(&mut buffer)?;

        for event in events {
            if Some(OsStr::new(watch.file)) == event.name {
                // directory events
                if event.mask.contains(EventMask::CREATE) {
                    // update watch
                    inotify.add_watch(&watch.path, WatchMask::MODIFY | WatchMask::MOVE_SELF)?;
                    watch.set_pos(0);
                }
            } else {
                // file events
                if !(event.mask.contains(EventMask::MOVE_SELF)
                    | event.mask.contains(EventMask::IGNORED))
                {
                    let metadata = fs::metadata(&watch.path)?;
                    let f = File::open(&watch.path)?;
                    let mut reader = BufReader::new(f);
                    reader.seek(SeekFrom::Start(watch.pos))?;

                    loop {
                        linebuffer.clear();
                        let bytes_read = reader.read_until(b'\n', &mut linebuffer)?;
                        if bytes_read == 0 {
                            break;
                        } else {
                            for map in &mut failures {
                                if String::from_utf8_lossy(&linebuffer[..])
                                    .contains(map.auth_failure.message)
                                {
                                    notify(*map)?;
                                }
                            }
                        }
                    }
                    watch.set_pos(metadata.len());
                }
            }
        }
    }
}
