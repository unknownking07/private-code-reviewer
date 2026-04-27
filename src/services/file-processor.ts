import fs from "fs";
import path from "path";
import { createHash } from "crypto";
import extractZip from "extract-zip";
import tar from "tar";
import { FileEntry } from "../utils/types";
import { logger } from "../utils/logger";

const SOLIDITY_EXTENSIONS = [".sol"];
const RUST_EXTENSIONS = [".rs"];
const MOVE_EXTENSIONS = [".move"];
const VYPER_EXTENSIONS = [".vy", ".vyper"];
const CAIRO_EXTENSIONS = [".cairo"];
const GO_EXTENSIONS = [".go"];
const TYPESCRIPT_EXTENSIONS = [".ts", ".tsx", ".js", ".jsx"];
const MAX_FILE_SIZE = 500 * 1024; // 500KB per file

export class FileProcessor {
  async processUpload(uploadPath: string): Promise<{ files: FileEntry[]; codeHash: string }> {
    const extractDir = uploadPath + "_extracted";
    fs.mkdirSync(extractDir, { recursive: true });

    try {
      await this.extractArchive(uploadPath, extractDir);
      const files = this.collectFiles(extractDir, extractDir);
      const codeHash = this.hashFiles(files);

      logger.info(`Processed upload: ${files.length} files, hash: ${codeHash.substring(0, 16)}...`);
      return { files, codeHash };
    } finally {
      // Clean up extracted files — code never persists
      fs.rmSync(extractDir, { recursive: true, force: true });
      fs.rmSync(uploadPath, { force: true });
      logger.info("Upload files securely deleted from TEE");
    }
  }

  private async extractArchive(archivePath: string, destDir: string): Promise<void> {
    const ext = path.extname(archivePath).toLowerCase();

    if (ext === ".zip") {
      await extractZip(archivePath, { dir: path.resolve(destDir) });
    } else if (ext === ".gz" || ext === ".tgz") {
      await tar.x({ file: archivePath, cwd: destDir });
    } else if (ext === ".tar") {
      await tar.x({ file: archivePath, cwd: destDir });
    } else {
      // Single file upload — just copy it
      const dest = path.join(destDir, path.basename(archivePath));
      fs.copyFileSync(archivePath, dest);
    }
  }

  private collectFiles(dir: string, baseDir: string): FileEntry[] {
    const files: FileEntry[] = [];

    const walk = (currentDir: string) => {
      for (const entry of fs.readdirSync(currentDir, { withFileTypes: true })) {
        const fullPath = path.join(currentDir, entry.name);

        if (entry.isDirectory()) {
          // Skip common non-source directories
          if (["node_modules", ".git", "target", "build", "artifacts", "cache"].includes(entry.name)) {
            continue;
          }
          walk(fullPath);
        } else if (entry.isFile()) {
          const ext = path.extname(entry.name).toLowerCase();
          let language: FileEntry["language"] = "unknown";

          if (SOLIDITY_EXTENSIONS.includes(ext)) language = "solidity";
          else if (RUST_EXTENSIONS.includes(ext)) language = "rust";
          else if (MOVE_EXTENSIONS.includes(ext)) language = "move";
          else if (VYPER_EXTENSIONS.includes(ext)) language = "vyper";
          else if (CAIRO_EXTENSIONS.includes(ext)) language = "cairo";
          else if (GO_EXTENSIONS.includes(ext)) language = "go";
          else if (TYPESCRIPT_EXTENSIONS.includes(ext)) language = "typescript";
          else continue; // Skip non-target files

          const stat = fs.statSync(fullPath);
          if (stat.size > MAX_FILE_SIZE) {
            // Don't log path (could leak directory structure / project identity).
            logger.warn(`Skipping oversized .${ext} file: ${stat.size}B > ${MAX_FILE_SIZE}B`);
            continue;
          }

          const content = fs.readFileSync(fullPath, "utf-8");
          const relativePath = path.relative(baseDir, fullPath);

          files.push({
            path: relativePath,
            content,
            language,
            size: stat.size,
          });
        }
      }
    };

    walk(dir);
    return files;
  }

  private hashFiles(files: FileEntry[]): string {
    const hash = createHash("sha256");
    for (const file of files.sort((a, b) => a.path.localeCompare(b.path))) {
      hash.update(file.path);
      hash.update(file.content);
    }
    return hash.digest("hex");
  }
}
