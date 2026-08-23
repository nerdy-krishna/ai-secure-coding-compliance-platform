import { sanitizeBrowserArtifacts } from "./artifact-sanitizer";
import { runBrowserFixture } from "./support";

export default function globalTeardown(): void {
  try {
    sanitizeBrowserArtifacts();
  } finally {
    runBrowserFixture("cleanup");
  }
}
