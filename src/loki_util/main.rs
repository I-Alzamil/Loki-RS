mod html_report;

use colored::*;
use dialoguer::{theme::ColorfulTheme, Select};
use glob::glob;
use serde_json::Value;
use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

const VERSION: &str = env!("CARGO_PKG_VERSION");
const YARA_FORGE_URL: &str =
    "https://github.com/YARAHQ/yara-forge/releases/latest/download/yara-forge-rules-core.zip";
const LOKI_RELEASES_URL: &str = "https://api.github.com/repos/Neo23x0/Loki-RS/releases";
const SIGNATURES_DIR: &str = "./signatures";
const TEMP_DIR: &str = "./tmp";

// Enable ANSI escape code support on Windows
#[cfg(windows)]
fn enable_ansi_support() {
    use windows::Win32::System::Console::{
        GetConsoleMode, GetStdHandle, SetConsoleMode, ENABLE_VIRTUAL_TERMINAL_PROCESSING,
        STD_ERROR_HANDLE, STD_OUTPUT_HANDLE,
    };

    unsafe {
        // Enable for stdout
        if let Ok(handle) = GetStdHandle(STD_OUTPUT_HANDLE) {
            let mut mode = std::mem::zeroed();
            if GetConsoleMode(handle, &mut mode).is_ok() {
                let _ = SetConsoleMode(handle, mode | ENABLE_VIRTUAL_TERMINAL_PROCESSING);
            }
        }
        // Enable for stderr
        if let Ok(handle) = GetStdHandle(STD_ERROR_HANDLE) {
            let mut mode = std::mem::zeroed();
            if GetConsoleMode(handle, &mut mode).is_ok() {
                let _ = SetConsoleMode(handle, mode | ENABLE_VIRTUAL_TERMINAL_PROCESSING);
            }
        }
    }
}

#[cfg(not(windows))]
fn enable_ansi_support() {
    // ANSI codes work natively on Unix-like systems
}

fn main() {
    // Enable ANSI color support on Windows
    enable_ansi_support();

    print_banner();

    let args: Vec<String> = std::env::args().collect();

    if args.len() < 2 {
        // Check if running in a TTY (interactive terminal)
        // If not, print usage instead of trying interactive mode
        if atty::is(atty::Stream::Stdin) {
            if let Err(e) = interactive_mode() {
                log_error(&format!("Interactive mode error: {}", e));
                std::process::exit(1);
            }
        } else {
            // Not running in a TTY (e.g., CI/CD, pipes, etc.)
            // Print usage information instead
            print_usage();
        }
        return;
    }

    let command = &args[1];
    match command.as_str() {
        "update" => {
            log_step("Starting signature update...");
            if let Err(e) = update_signatures() {
                log_error(&format!("Error updating signatures: {}", e));
                std::process::exit(1);
            }
            log_success("Signatures updated successfully!");
        }
        "upgrade" => {
            log_step("Starting Loki-RS upgrade...");
            if let Err(e) = upgrade_loki() {
                log_error(&format!("Error upgrading Loki-RS: {}", e));
                std::process::exit(1);
            }
            log_success("Loki-RS upgraded successfully!");
        }
        "html" => {
            if let Err(e) = handle_html_command(&args[2..]) {
                log_error(&format!("Error generating HTML report: {}", e));
                std::process::exit(1);
            }
        }
        "--help" | "-h" => {
            print_usage();
        }
        _ => {
            log_error(&format!("Unknown command: {}", command));
            print_usage();
            std::process::exit(1);
        }
    }
}

fn print_banner() {
    println!(
        "{}",
        "------------------------------------------------------------------------".bright_green()
    );
    println!(
        "{}",
        "   ::             x.                                                    ".bright_green()
    );
    println!(
        "{}",
        "   ;.             xX    ______ _____________ _________                  ".bright_green()
    );
    println!(
        "{}",
        "   .x            :$x    ___  / __  __ \\__  //_/___  _/                  ".bright_green()
    );
    println!(
        "{}",
        "    ++           Xx     __  /  _  / / /_  ,<   __  /                    ".bright_green()
    );
    println!(
        "{}",
        "    .X:  ..;.   ;+.     _  /___/ /_/ /_  /| | __/ /                     ".bright_green()
    );
    println!(
        "{}",
        "     :xx +XXX;+::.      /_____/\\____/ /_/ |_| /___/                     ".bright_green()
    );
    println!(
        "{}",
        "       :xx+$;.:.        High-Performance YARA & IOC Scanner             ".bright_green()
    );
    println!(
        "{}",
        "          .X+:;;                                                        ".bright_green()
    );
    println!(
        "           ;  :.        Version {} (Rust)                               ",
        VERSION
    );
    println!(
        "{}",
        "        .    x+         Florian Roth 2026                               ".bright_green()
    );
    println!(
        "{}",
        "         :   +                                                          ".bright_green()
    );
    println!(
        "{}",
        "------------------------------------------------------------------------".bright_green()
    );
    println!();
}

fn print_usage() {
    println!("Usage: loki-util <command>");
    println!();
    println!("Commands:");
    println!(
        "  {}   - Update YARA rules (YARA-Forge Core)",
        "update".green()
    );
    println!(
        "  {}  - Update Loki-RS program and signatures",
        "upgrade".green()
    );
    println!(
        "  {}    - Generate HTML report from JSONL file(s)",
        "html".green()
    );
    println!();
    println!("HTML Report Generation:");
    println!("  loki-util html --input <file.jsonl> --output <report.html>");
    println!("  loki-util html --input \"*.jsonl\" --combine --output combined.html");
    println!();
    println!("Options:");
    println!("  --input <file|glob>  - Input JSONL file or glob pattern");
    println!("  --output <file.html> - Output HTML file (optional, defaults to input.html)");
    println!("  --combine            - Combine multiple JSONL files into one report");
    println!("  --title <str>       - Override report title");
    println!("  --host <str>         - Override hostname");
    println!();
}

fn log_info(msg: &str) {
    println!(" {} {}", "[*]".blue(), msg);
}

fn log_success(msg: &str) {
    println!(" {} {}", "[+]".green(), msg);
}

fn log_error(msg: &str) {
    eprintln!(" {} {}", "[!]".red(), msg);
}

fn log_warn(msg: &str) {
    println!(" {} {}", "[!]".yellow(), msg);
}

fn log_step(msg: &str) {
    println!(" {} {}", "[>]".cyan(), msg);
}

fn interactive_mode() -> Result<(), Box<dyn std::error::Error>> {
    let options = vec!["Update signatures", "Upgrade Loki-RS", "Exit"];

    let selection = Select::with_theme(&ColorfulTheme::default())
        .with_prompt("What would you like to do?")
        .default(0)
        .items(&options)
        .interact()?;

    match selection {
        0 => {
            log_step("Starting signature update...");
            update_signatures()?;
            log_success("Signatures updated successfully!");
        }
        1 => {
            log_step("Starting Loki-RS upgrade...");
            upgrade_loki()?;
            log_success("Loki-RS upgraded successfully!");
        }
        _ => {
            println!("Exiting...");
        }
    }

    Ok(())
}

fn update_signatures() -> Result<(), Box<dyn std::error::Error>> {
    update_signatures_with(Path::new(SIGNATURES_DIR), download_file)
}

// Own only this update's staging directory; never remove a shared ./tmp tree.
struct SignatureUpdateDir {
    path: PathBuf,
    cleanup: bool,
}

impl SignatureUpdateDir {
    fn new(signatures_dir: &Path) -> io::Result<Self> {
        use std::sync::atomic::{AtomicU64, Ordering};
        static NEXT_ID: AtomicU64 = AtomicU64::new(0);
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        loop {
            let path = signatures_dir.join(format!(
                ".yara-update-{}-{}-{}",
                std::process::id(),
                timestamp,
                NEXT_ID.fetch_add(1, Ordering::Relaxed)
            ));
            match fs::create_dir(&path) {
                Ok(()) => {
                    return Ok(Self {
                        path,
                        cleanup: true,
                    })
                }
                Err(e) if e.kind() == io::ErrorKind::AlreadyExists => continue,
                Err(e) => return Err(e),
            }
        }
    }
}

impl Drop for SignatureUpdateDir {
    fn drop(&mut self) {
        if self.cleanup {
            let _ = fs::remove_dir_all(&self.path);
        }
    }
}

fn update_signatures_with<F>(
    signatures_dir: &Path,
    download: F,
) -> Result<(), Box<dyn std::error::Error>>
where
    F: FnOnce(&str, &Path) -> Result<(), Box<dyn std::error::Error>>,
{
    fs::create_dir_all(signatures_dir)?;
    // Stage on the destination filesystem so installing and restoring rules use renames.
    let mut work = SignatureUpdateDir::new(signatures_dir)?;
    let zip_path = work.path.join("yara-forge-rules-core.zip");
    let staged_yara = work.path.join("yara");
    log_info("Downloading YARA rules from yara-forge...");
    download(YARA_FORGE_URL, &zip_path)?;
    extract_yara_rules(&zip_path, &staged_yara)?;
    validate_yara_rules(&staged_yara)?;

    // IOC files remain optional local content. Finish fallible preparation before
    // replacing rules, and never overwrite existing IOC files.
    ensure_default_ioc_files(signatures_dir)?;
    install_yara_rules(&mut work, &signatures_dir.join("yara"), |src, dst| {
        fs::rename(src, dst)
    })?;
    log_success("YARA rules updated from yara-forge");
    Ok(())
}

fn download_file(url: &str, output_path: &Path) -> Result<(), Box<dyn std::error::Error>> {
    let resp = ureq::get(url).header("User-Agent", "loki-util").call()?;

    let mut reader = resp.into_body().into_reader();
    let mut file = fs::File::create(output_path)?;
    io::copy(&mut reader, &mut file)?;

    Ok(())
}

fn fetch_url_content(url: &str) -> Result<String, Box<dyn std::error::Error>> {
    let mut resp = ureq::get(url).header("User-Agent", "loki-util").call()?;
    let body = resp.body_mut().read_to_string()?;
    Ok(body)
}

fn extract_yara_rules(zip_path: &Path, yara_dest: &Path) -> Result<(), Box<dyn std::error::Error>> {
    let file = fs::File::open(zip_path)?;
    let mut archive = zip::ZipArchive::new(std::io::BufReader::new(file))?;
    fs::create_dir(yara_dest)?;

    for i in 0..archive.len() {
        let mut file = archive.by_index(i)?;
        if file.is_dir() || !file.name().ends_with(".yar") {
            continue;
        }
        let filename = Path::new(file.name())
            .file_name()
            .ok_or("Invalid YARA filename")?;
        // Flatten archive paths as before, but reject duplicate names instead of
        // silently replacing one downloaded rule file with another.
        let mut outfile = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(yara_dest.join(filename))?;
        io::copy(&mut file, &mut outfile)?;
        // The scanner concatenates file contents without a separator. End each
        // staged source with a newline so trailing comments cannot hide rules.
        outfile.write_all(b"\n")?;
    }
    Ok(())
}

fn compile_downloaded_yara_rules(
    source: &str,
) -> Result<yara_x::Rules, Box<dyn std::error::Error>> {
    let mut compiler = yara_x::Compiler::new();
    // Match the external variables available in the scanner.
    for name in ["filename", "filepath", "extension", "filetype", "owner"] {
        compiler.define_global(name, "")?;
    }
    compiler.add_source(source)?;
    Ok(compiler.build())
}

fn validate_yara_rules(yara_dir: &Path) -> Result<(), Box<dyn std::error::Error>> {
    let mut files: Vec<_> = fs::read_dir(yara_dir)?.collect::<Result<_, _>>()?;
    files.sort_by_key(|entry| entry.file_name());
    let mut combined_source = String::new();
    let mut expected_rules = 0;
    for file in files {
        let source = fs::read_to_string(file.path())?;
        // The scanner first compiles each file separately, then concatenates
        // their raw contents. Validate both stages before changing installed rules.
        let rules = compile_downloaded_yara_rules(&source).map_err(|e| {
            format!(
                "Invalid downloaded YARA file {}: {}",
                file.path().display(),
                e
            )
        })?;
        expected_rules += rules.iter().count();
        combined_source.push_str(&source);
    }
    let rules = compile_downloaded_yara_rules(&combined_source)?;
    let combined_count = rules.iter().count();
    if combined_count == 0 {
        return Err("Downloaded archive contains no usable YARA rules".into());
    }
    if combined_count != expected_rules {
        return Err("Downloaded YARA files lose rules when combined by the scanner".into());
    }
    Ok(())
}

fn is_yara_rule(path: &Path) -> bool {
    let ext = path.extension().and_then(|e| e.to_str()).unwrap_or("");
    path.is_file() && (ext.eq_ignore_ascii_case("yar") || ext.eq_ignore_ascii_case("yara"))
}

fn install_yara_rules<F>(
    work: &mut SignatureUpdateDir,
    yara_dir: &Path,
    mut rename: F,
) -> Result<(), Box<dyn std::error::Error>>
where
    F: FnMut(&Path, &Path) -> io::Result<()>,
{
    let staged_yara = work.path.join("yara");
    let backup_dir = work.path.join("backup");
    fs::create_dir_all(yara_dir)?;
    fs::create_dir(&backup_dir)?;
    let mut old_rules = Vec::new();
    for entry in fs::read_dir(yara_dir)? {
        let entry = entry?;
        if is_yara_rule(&entry.path()) {
            old_rules.push(entry.file_name());
        }
    }
    old_rules.sort();
    let mut new_rules = Vec::new();
    for entry in fs::read_dir(&staged_yara)? {
        let name = entry?.file_name();
        new_rules.push(name);
    }
    new_rules.sort();

    let mut backed_up = Vec::new();
    let mut installed = Vec::new();
    let result = (|| -> io::Result<()> {
        for name in &old_rules {
            rename(&yara_dir.join(name), &backup_dir.join(name))?;
            backed_up.push(name);
        }
        for name in &new_rules {
            let destination = yara_dir.join(name);
            // Check after backups so case-only filename changes work on
            // case-insensitive filesystems. Preserve all non-rule local content.
            match fs::symlink_metadata(&destination) {
                Ok(_) => {
                    return Err(io::Error::new(
                        io::ErrorKind::AlreadyExists,
                        format!("YARA update would overwrite {}", destination.display()),
                    ));
                }
                Err(e) if e.kind() == io::ErrorKind::NotFound => {}
                Err(e) => return Err(e),
            }
            rename(&staged_yara.join(name), &destination)?;
            installed.push(name);
        }
        Ok(())
    })();
    if let Err(error) = result {
        let mut rollback_errors = Vec::new();
        for name in installed.iter().rev() {
            if let Err(e) = rename(&yara_dir.join(name), &staged_yara.join(name)) {
                rollback_errors.push(e.to_string());
            }
        }
        for name in backed_up.iter().rev() {
            if let Err(e) = rename(&backup_dir.join(name), &yara_dir.join(name)) {
                rollback_errors.push(e.to_string());
            }
        }
        if !rollback_errors.is_empty() {
            // Keep backups if the filesystem also prevents rollback; never
            // delete the only remaining copy of an installed rule.
            work.cleanup = false;
            return Err(format!(
                "YARA installation failed: {}. Restoration failed: {}. Recovery files retained in {}",
                error,
                rollback_errors.join("; "),
                work.path.display()
            ).into());
        }
        return Err(error.into());
    }
    Ok(())
}

fn ensure_default_ioc_files(signatures_dir: &Path) -> Result<(), Box<dyn std::error::Error>> {
    let iocs_dir = signatures_dir.join("iocs");
    fs::create_dir_all(&iocs_dir)?;

    let defaults = [
        ("hash-iocs.txt", "# Optional custom hash IOCs\n"),
        ("filename-iocs.txt", "# Optional custom filename IOCs\n"),
        ("c2-iocs.txt", "# Optional custom C2 IOCs\n"),
        ("keywords.txt", "# Optional custom keyword IOCs\n"),
    ];

    for (name, content) in defaults {
        let path = iocs_dir.join(name);
        if !path.exists() {
            fs::write(path, content)?;
        }
    }

    Ok(())
}

fn get_platform_string() -> String {
    let os = std::env::consts::OS;
    let arch = std::env::consts::ARCH;

    // Match the naming convention used in releases
    // e.g. loki-windows-x86_64.zip, loki-linux-x86_64.tar.gz

    let os_str = match os {
        "windows" => "windows",
        "linux" => "linux",
        "macos" => "macos",
        _ => return "unknown".to_string(),
    };

    let arch_str = match arch {
        "x86_64" => "x86_64",
        "aarch64" => "aarch64", // macOS M1/M2
        _ => return "unknown".to_string(),
    };

    format!("loki-{}-{}", os_str, arch_str)
}

fn extract_zip(zip_path: &Path, dest_dir: &Path) -> Result<(), Box<dyn std::error::Error>> {
    let file = fs::File::open(zip_path)?;
    let mut archive = zip::ZipArchive::new(std::io::BufReader::new(file))?;

    for i in 0..archive.len() {
        let mut file = archive.by_index(i)?;
        let outpath = dest_dir.join(file.mangled_name());

        if (&*file.name()).ends_with('/') {
            fs::create_dir_all(&outpath)?;
        } else {
            if let Some(p) = outpath.parent() {
                if !p.exists() {
                    fs::create_dir_all(&p)?;
                }
            }
            let mut outfile = fs::File::create(&outpath)?;
            io::copy(&mut file, &mut outfile)?;
        }
    }
    Ok(())
}

fn extract_tar_gz(tar_path: &Path, dest_dir: &Path) -> Result<(), Box<dyn std::error::Error>> {
    let status = Command::new("tar")
        .arg("-xzf")
        .arg(tar_path)
        .arg("-C")
        .arg(dest_dir)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()?;

    if !status.success() {
        return Err("Failed to extract tar.gz archive".into());
    }
    Ok(())
}

fn install_updates(source_dir: &Path) -> Result<(), Box<dyn std::error::Error>> {
    // Find executables in source_dir (could be nested in a folder)
    let mut root_dir = source_dir.to_path_buf();

    // Check if there is a single directory inside
    let entries: Vec<_> = fs::read_dir(source_dir)?.collect::<Result<_, _>>()?;
    if entries.len() == 1 && entries[0].path().is_dir() {
        root_dir = entries[0].path();
    }

    let current_exe = std::env::current_exe()?;
    let current_dir = current_exe.parent().ok_or("Cannot get current directory")?;

    // Files to update
    let targets = if cfg!(windows) {
        vec!["loki.exe", "loki-util.exe"]
    } else {
        vec!["loki", "loki-util"]
    };

    for target in targets {
        let src = root_dir.join(target);
        if src.exists() {
            let dst = current_dir.join(target);

            // On Windows, we can't overwrite running executable. Rename it first.
            if dst.exists() {
                let backup = current_dir.join(format!("{}.old", target));
                // Remove old backup if exists
                if backup.exists() {
                    let _ = fs::remove_file(&backup);
                }

                // Rename current to backup
                match fs::rename(&dst, &backup) {
                    Ok(_) => log_info(&format!("Backup created: {}", backup.display())),
                    Err(e) => log_warn(&format!("Failed to rename {} to backup: {} (might be acceptable if we can overwrite)", target, e)),
                }
            }

            // Copy new file
            fs::copy(&src, &dst)?;
            log_success(&format!("Updated: {}", target));

            // Set executable permissions on Unix
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let mut perms = fs::metadata(&dst)?.permissions();
                perms.set_mode(0o755);
                fs::set_permissions(&dst, perms)?;
            }
        }
    }

    Ok(())
}

fn upgrade_loki_binary() -> Result<(), Box<dyn std::error::Error>> {
    let platform = get_platform_string();
    if platform == "unknown" {
        return Err("Could not determine platform (OS/Arch) for automatic update.".into());
    }

    log_info(&format!("Detected platform: {}", platform));

    // 1. Get latest release info
    log_info("Checking for updates from GitHub...");
    let json_content = fetch_latest_release_info()?;
    let releases: Value = serde_json::from_str(&json_content)?;

    // Get the first release from the list (latest)
    let latest_release = if releases.is_array() {
        releases.get(0).ok_or("No releases found")?
    } else if releases.is_object() && releases.get("tag_name").is_some() {
        &releases
    } else {
        return Err("Invalid response from GitHub API".into());
    };

    let tag_name = latest_release["tag_name"]
        .as_str()
        .ok_or("No tag_name in release info")?;
    log_info(&format!("Latest version available: {}", tag_name));

    // 2. Find matching asset
    let assets = latest_release["assets"]
        .as_array()
        .ok_or("No assets in release info")?;
    let mut download_url = None;
    let mut asset_name = "";

    for asset in assets {
        let name = asset["name"].as_str().unwrap_or("");
        if name.contains(&platform) && (name.ends_with(".zip") || name.ends_with(".tar.gz")) {
            download_url = asset["browser_download_url"].as_str();
            asset_name = name;
            break;
        }
    }

    let download_url = download_url.ok_or(format!(
        "No matching release found for platform: {}",
        platform
    ))?;
    log_info(&format!("Found matching release: {}", asset_name));

    // Create temp directory
    fs::create_dir_all(TEMP_DIR)?;

    // 3. Download
    let archive_path = Path::new(TEMP_DIR).join(asset_name);
    log_info("Downloading release...");
    download_file(download_url, &archive_path)?;

    // 4. Extract
    log_info("Extracting update...");
    let extract_dir = Path::new(TEMP_DIR).join("update_extracted");
    fs::create_dir_all(&extract_dir)?;

    if asset_name.ends_with(".zip") {
        extract_zip(&archive_path, &extract_dir)?;
    } else {
        // tar.gz
        extract_tar_gz(&archive_path, &extract_dir)?;
    }

    // 5. Replace files
    install_updates(&extract_dir)?;

    // Clean up
    let _ = fs::remove_file(&archive_path);
    let _ = fs::remove_dir_all(&extract_dir);

    Ok(())
}

fn fetch_latest_release_info() -> Result<String, Box<dyn std::error::Error>> {
    fetch_url_content(LOKI_RELEASES_URL)
}

fn upgrade_loki() -> Result<(), Box<dyn std::error::Error>> {
    log_info("Upgrading Loki-RS via GitHub Releases...");

    // Attempt binary upgrade
    if let Err(e) = upgrade_loki_binary() {
        log_error(&format!("Automatic binary upgrade failed: {}", e));
        log_error("Please update Loki-RS manually.");
        return Err(e);
    }

    // Update signatures
    update_signatures()?;

    Ok(())
}

fn handle_html_command(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    let mut input: Option<String> = None;
    let mut output: Option<String> = None;
    let mut combine = false;
    let mut title: Option<String> = None;
    let mut host: Option<String> = None;

    // Parse arguments
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--input" | "-i" => {
                if i + 1 < args.len() {
                    input = Some(args[i + 1].clone());
                    i += 2;
                } else {
                    return Err("--input requires a value".into());
                }
            }
            "--output" | "-o" => {
                if i + 1 < args.len() {
                    output = Some(args[i + 1].clone());
                    i += 2;
                } else {
                    return Err("--output requires a value".into());
                }
            }
            "--combine" | "-c" => {
                combine = true;
                i += 1;
            }
            "--title" | "-t" => {
                if i + 1 < args.len() {
                    title = Some(args[i + 1].clone());
                    i += 2;
                } else {
                    return Err("--title requires a value".into());
                }
            }
            "--host" | "-h" => {
                if i + 1 < args.len() {
                    host = Some(args[i + 1].clone());
                    i += 2;
                } else {
                    return Err("--host requires a value".into());
                }
            }
            "--help" => {
                print_usage();
                return Ok(());
            }
            _ => {
                return Err(format!("Unknown argument: {}", args[i]).into());
            }
        }
    }

    let input_path = input.ok_or("--input is required")?;

    // Expand glob pattern if needed
    let input_files = expand_inputs(&input_path)?;

    if input_files.is_empty() {
        return Err(format!("No files found matching: {}", input_path).into());
    }

    log_step(&format!(
        "Found {} JSONL file(s) to process",
        input_files.len()
    ));

    if combine || input_files.len() > 1 {
        // Combined report mode
        log_step("Generating combined HTML report...");
        let combined_data = html_report::parse_multiple_jsonl_files(&input_files)?;

        let output_path = output.unwrap_or_else(|| "combined_report.html".to_string());
        let version = combined_data
            .sources
            .first()
            .and_then(|s| s.version.as_ref())
            .map(|v| v.clone())
            .unwrap_or_else(|| VERSION.to_string());

        html_report::render_combined_html(&combined_data, &version, &output_path)?;
        log_success(&format!("Combined HTML report written to: {}", output_path));
    } else {
        // Single file mode
        log_step("Generating HTML report...");
        let output_path = html_report::generate_single_report(
            &input_files[0],
            output.as_deref(),
            title.as_deref(),
            host.as_deref(),
        )?;
        log_success(&format!("HTML report written to: {}", output_path));
    }

    Ok(())
}

fn expand_inputs(pattern: &str) -> Result<Vec<String>, Box<dyn std::error::Error>> {
    let mut files = Vec::new();

    // Check if pattern contains glob characters
    if pattern.contains('*') || pattern.contains('?') || pattern.contains('[') {
        // Use glob pattern matching
        let matches = glob(pattern)?;
        for entry in matches {
            match entry {
                Ok(path) => {
                    if path.is_file() && path.extension().and_then(|s| s.to_str()) == Some("jsonl")
                    {
                        files.push(path.to_string_lossy().to_string());
                    }
                }
                Err(e) => {
                    log_warn(&format!("Error matching glob pattern: {}", e));
                }
            }
        }
    } else {
        // Single file path
        let path = Path::new(pattern);
        if !path.exists() {
            return Err(format!("File not found: {}", pattern).into());
        }
        if !path.is_file() {
            return Err(format!("Path is not a file: {}", pattern).into());
        }
        files.push(pattern.to_string());
    }

    // Sort for consistent ordering
    files.sort();

    Ok(files)
}

#[cfg(test)]
mod signature_update_tests {
    use super::*;
    use std::io::Write;

    const NEW_RULE: &str = "rule new_rule { condition: filename != \"\" }";

    fn installed_signatures() -> SignatureUpdateDir {
        let fixture = SignatureUpdateDir::new(&std::env::temp_dir()).unwrap();
        fs::create_dir(fixture.path.join("yara")).unwrap();
        fs::write(fixture.path.join("yara/old.yar"), "original rules").unwrap();
        fixture
    }

    fn write_archive(path: &Path, entries: &[(&str, &str)]) {
        let mut archive = zip::ZipWriter::new(fs::File::create(path).unwrap());
        for (name, content) in entries {
            archive
                .start_file(*name, zip::write::SimpleFileOptions::default())
                .unwrap();
            archive.write_all(content.as_bytes()).unwrap();
        }
        archive.finish().unwrap();
    }

    fn assert_original_rules(fixture: &SignatureUpdateDir) {
        assert_eq!(
            fs::read_to_string(fixture.path.join("yara/old.yar")).unwrap(),
            "original rules"
        );
    }

    #[test]
    fn failed_download_preserves_installed_rules() {
        let fixture = installed_signatures();
        let result = update_signatures_with(&fixture.path, |_, path| {
            fs::write(path, "partial download")?;
            Err(io::Error::new(io::ErrorKind::ConnectionReset, "download failed").into())
        });
        assert!(result.is_err());
        assert_original_rules(&fixture);
        assert_eq!(fs::read_dir(&fixture.path).unwrap().count(), 1);
    }

    #[test]
    fn corrupt_archive_preserves_installed_rules() {
        let fixture = installed_signatures();
        let result = update_signatures_with(&fixture.path, |_, path| {
            fs::write(path, "not a zip")?;
            Ok(())
        });
        assert!(result.is_err());
        assert_original_rules(&fixture);
        assert_eq!(fs::read_dir(&fixture.path).unwrap().count(), 1);
    }

    #[test]
    fn empty_or_invalid_rules_preserve_installed_rules() {
        for entries in [
            vec![],
            vec![("README.txt", "no rules")],
            vec![("empty.yar", "// only a comment")],
            vec![("invalid.yar", "rule invalid { condition: }")],
            vec![
                ("a.yar", "rule first { condition: true }"),
                ("b.yar", "rule second { condition: first }"),
            ],
            vec![
                ("first/rules.yar", NEW_RULE),
                ("second/rules.yar", NEW_RULE),
            ],
        ] {
            let fixture = installed_signatures();
            let result = update_signatures_with(&fixture.path, |_, path| {
                write_archive(path, &entries);
                Ok(())
            });
            assert!(result.is_err(), "archive should be rejected: {:?}", entries);
            assert_original_rules(&fixture);
            assert_eq!(fs::read_dir(&fixture.path).unwrap().count(), 1);
        }
    }

    #[test]
    fn successful_update_replaces_rules_and_preserves_local_content() {
        let fixture = installed_signatures();
        fs::write(fixture.path.join("yara/legacy.YARA"), "legacy rules").unwrap();
        fs::write(fixture.path.join("yara/README.txt"), "local notes").unwrap();
        fs::create_dir(fixture.path.join("yara/custom")).unwrap();
        fs::write(
            fixture.path.join("yara/custom/retained.yar"),
            "nested rules",
        )
        .unwrap();
        fs::create_dir(fixture.path.join("iocs")).unwrap();
        fs::write(fixture.path.join("iocs/hash-iocs.txt"), "custom IOC").unwrap();
        update_signatures_with(&fixture.path, |_, path| {
            write_archive(path, &[("yara-forge/new.yar", NEW_RULE)]);
            Ok(())
        })
        .unwrap();
        assert!(!fixture.path.join("yara/old.yar").exists());
        assert!(!fixture.path.join("yara/legacy.YARA").exists());
        assert_eq!(
            fs::read_to_string(fixture.path.join("yara/new.yar")).unwrap(),
            format!("{NEW_RULE}\n")
        );
        for (path, expected) in [
            ("yara/README.txt", "local notes"),
            ("yara/custom/retained.yar", "nested rules"),
            ("iocs/hash-iocs.txt", "custom IOC"),
        ] {
            assert_eq!(
                fs::read_to_string(fixture.path.join(path)).unwrap(),
                expected
            );
        }
        assert!(fixture.path.join("iocs/filename-iocs.txt").is_file());
        assert_eq!(fs::read_dir(&fixture.path).unwrap().count(), 2);
    }

    #[test]
    fn trailing_comments_cannot_hide_the_next_rule_file() {
        let fixture = installed_signatures();
        update_signatures_with(&fixture.path, |_, path| {
            write_archive(
                path,
                &[
                    (
                        "a.yar",
                        "rule first { condition: true } // trailing comment",
                    ),
                    ("b.yar", "rule second { condition: true }"),
                ],
            );
            Ok(())
        })
        .unwrap();
        let first = fs::read_to_string(fixture.path.join("yara/a.yar")).unwrap();
        let second = fs::read_to_string(fixture.path.join("yara/b.yar")).unwrap();
        for source in [format!("{first}{second}"), format!("{second}{first}")] {
            assert_eq!(
                compile_downloaded_yara_rules(&source)
                    .unwrap()
                    .iter()
                    .count(),
                2
            );
        }
    }

    #[test]
    fn case_only_rule_filename_change_replaces_installed_rule() {
        let fixture = installed_signatures();
        fs::rename(
            fixture.path.join("yara/old.yar"),
            fixture.path.join("yara/RULES.YAR"),
        )
        .unwrap();
        update_signatures_with(&fixture.path, |_, path| {
            write_archive(path, &[("rules.yar", NEW_RULE)]);
            Ok(())
        })
        .unwrap();
        let names: Vec<_> = fs::read_dir(fixture.path.join("yara"))
            .unwrap()
            .map(|entry| entry.unwrap().file_name())
            .collect();
        assert_eq!(names, vec![std::ffi::OsString::from("rules.yar")]);
        assert_eq!(
            fs::read_to_string(fixture.path.join("yara/rules.yar")).unwrap(),
            format!("{NEW_RULE}\n")
        );
    }

    #[test]
    fn filename_collision_preserves_local_directory_and_restores_rules() {
        let fixture = installed_signatures();
        fs::create_dir(fixture.path.join("yara/new.yar")).unwrap();
        fs::write(fixture.path.join("yara/new.yar/local.txt"), "local data").unwrap();
        let result = update_signatures_with(&fixture.path, |_, path| {
            write_archive(path, &[("new.yar", NEW_RULE)]);
            Ok(())
        });
        assert!(result.is_err());
        assert_original_rules(&fixture);
        assert_eq!(
            fs::read_to_string(fixture.path.join("yara/new.yar/local.txt")).unwrap(),
            "local data"
        );
    }

    #[test]
    fn partial_install_failure_restores_prior_rules() {
        let fixture = installed_signatures();
        let mut work = SignatureUpdateDir::new(&fixture.path).unwrap();
        let staged_yara = work.path.join("yara");
        fs::create_dir(&staged_yara).unwrap();
        fs::write(staged_yara.join("a.yar"), NEW_RULE).unwrap();
        fs::write(staged_yara.join("b.yar"), NEW_RULE).unwrap();
        let result = install_yara_rules(&mut work, &fixture.path.join("yara"), |src, dst| {
            if src == staged_yara.join("b.yar") {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "install failed",
                ));
            }
            fs::rename(src, dst)
        });
        assert!(result.is_err());
        assert_original_rules(&fixture);
        assert!(!fixture.path.join("yara/a.yar").exists());
        assert!(!fixture.path.join("yara/b.yar").exists());
        assert!(work.cleanup);
    }

    #[test]
    fn failed_rollback_retains_recovery_files() {
        let fixture = installed_signatures();
        let mut work = SignatureUpdateDir::new(&fixture.path).unwrap();
        let staged_yara = work.path.join("yara");
        fs::create_dir(&staged_yara).unwrap();
        fs::write(staged_yara.join("new.yar"), NEW_RULE).unwrap();
        let recovery_path = work.path.clone();
        let result = install_yara_rules(&mut work, &fixture.path.join("yara"), |src, dst| {
            if src.parent() != Some(fixture.path.join("yara").as_path()) {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "rename failed",
                ));
            }
            fs::rename(src, dst)
        });
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("Recovery files retained"));
        assert!(!work.cleanup);
        drop(work);
        assert_eq!(
            fs::read_to_string(recovery_path.join("backup/old.yar")).unwrap(),
            "original rules"
        );
    }
}
