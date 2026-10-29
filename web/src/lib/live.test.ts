import { afterEach, describe, expect, it, vi } from "vitest";

class FakeEventSource {
  static last: FakeEventSource | null = null;
  url: string;
  closed = false;
  handlers = new Map<string, (e: MessageEvent) => void>();
  constructor(url: string) {
    this.url = url;
    FakeEventSource.last = this;
  }
  addEventListener(name: string, fn: (e: MessageEvent) => void) {
    this.handlers.set(name, fn);
  }
  close() {
    this.closed = true;
  }
  emit(name: string, data: unknown) {
    this.handlers.get(name)?.({ data: JSON.stringify(data) } as MessageEvent);
  }
}

describe("live", () => {
  afterEach(() => {
    vi.unstubAllGlobals();
    vi.resetModules();
  });

  it("shares one stream and calls only the subscribers of a kind", async () => {
    vi.stubGlobal("EventSource", FakeEventSource);
    const { subscribe } = await import("./live");
    const containers = vi.fn();
    const jobs = vi.fn();
    const off1 = subscribe(["containers"], containers);
    const first = FakeEventSource.last!;
    const off2 = subscribe(["jobs"], jobs);
    expect(FakeEventSource.last).toBe(first);
    expect(first.url).toBe("/api/v1/events");
    first.emit("change", { type: "containers" });
    expect(containers).toHaveBeenCalledTimes(1);
    expect(jobs).not.toHaveBeenCalled();
    first.emit("change", "not json{");
    off1();
    expect(first.closed).toBe(false);
    off2();
    expect(first.closed).toBe(true);
  });

  it("reports when pushing is unavailable", async () => {
    vi.stubGlobal("EventSource", undefined);
    const { liveAvailable } = await import("./live");
    expect(liveAvailable()).toBe(false);
  });
});

describe("stripControl", () => {
  it("removes terminal escapes and carriage returns", async () => {
    const { stripControl } = await import("../pages/ContainerConsole");
    expect(stripControl("\x1b[1;32mok\x1b[0m\r\n/ # \x1b[6n")).toBe("ok\n/ # ");
  });
});
