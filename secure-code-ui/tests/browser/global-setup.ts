import { runBrowserFixture } from "./support";

export default function globalSetup(): void {
  const fixture = runBrowserFixture("setup");
  process.env.SCCAP_BROWSER_FIXTURE_JSON = JSON.stringify(fixture);
}
