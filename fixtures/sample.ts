export class SampleAnalyzer {
  public name = "demo";
  private secretUrl = "mysql://demo:password123@example.test/app";

  public process(a: boolean, b: string[], c: string, d: string, e: string, f: string): void {
    if (a) {
      for (const item of b) {
        if (item === c) {
          eval(item);
        }
      }
    }

    const apiKey = "AKIA1111111111111111";
    console.log(apiKey, this.secretUrl, d, e, f);
  }
}

test("sleeps without assertion", async () => {
  await new Promise((resolve) => setTimeout(resolve, 1));
});
