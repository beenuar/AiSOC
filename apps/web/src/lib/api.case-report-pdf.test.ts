import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { ApiError, AUTH_TOKEN_KEY, casesApi } from "./api";

const CASE_ID = "11111111-1111-4111-8111-111111111111";
const RUN_ID = "22222222-2222-4222-8222-222222222222";
const PATH = `/api/v1/cases/${CASE_ID}/investigations/${RUN_ID}/report.pdf`;

const fetchMock = vi.fn<typeof fetch>();
const createObjectURL = vi.fn<(blob: Blob | MediaSource) => string>(() => "blob:case-report");
const revokeObjectURL = vi.fn();

beforeEach(() => {
  window.localStorage.clear();
  window.localStorage.setItem(AUTH_TOKEN_KEY, "report-download-token");
  vi.stubGlobal("fetch", fetchMock);
  vi.stubGlobal("URL", class extends URL {
    static createObjectURL = createObjectURL;
    static revokeObjectURL = revokeObjectURL;
  });
});

afterEach(() => {
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
  vi.clearAllMocks();
  window.localStorage.clear();
});

describe("casesApi.downloadReportPdf", () => {
  it.each([
    [404, { detail: "Run not found" }, "Run not found"],
    [409, { detail: "Investigation is running" }, "Investigation is running"],
    [422, { detail: [{ msg: "Invalid run identifier" }] }, "Invalid run identifier"],
  ])("shows the API reason for HTTP %s and preserves the raw body", async (status, body, message) => {
    const raw = JSON.stringify(body);
    fetchMock.mockResolvedValue(new Response(raw, { status }));

    const error = await casesApi.downloadReportPdf(CASE_ID, RUN_ID).catch((err: unknown) => err);

    expect(error).toBeInstanceOf(ApiError);
    expect(error).toMatchObject({ message, status, body: raw });
    expect(createObjectURL).not.toHaveBeenCalled();
  });

  it.each(["", "<html>Bad gateway</html>"])("uses the HTTP status when no API detail is available (%j)", async (raw) => {
    fetchMock.mockResolvedValue(new Response(raw, { status: 502 }));

    await expect(casesApi.downloadReportPdf(CASE_ID, RUN_ID)).rejects.toMatchObject({
      message: "PDF download failed (502)", status: 502, body: raw,
    });
    expect(createObjectURL).not.toHaveBeenCalled();
  });

  it("still downloads the PDF using the selected run and authenticated transport", async () => {
    const pdf = "%PDF-1.4\nfixture";
    fetchMock.mockResolvedValue(new Response(pdf, { headers: { "Content-Type": "application/pdf" } }));
    let download: { href: string; filename: string } | undefined;
    vi.spyOn(HTMLAnchorElement.prototype, "click").mockImplementation(function (this: HTMLAnchorElement) {
      download = { href: this.href, filename: this.download };
    });

    await casesApi.downloadReportPdf(CASE_ID, RUN_ID);

    expect(fetchMock).toHaveBeenCalledWith(PATH, expect.objectContaining({
      headers: expect.objectContaining({ Authorization: "Bearer report-download-token" }),
    }));
    expect(download).toEqual({ href: "blob:case-report", filename: `aisoc-report-${RUN_ID}.pdf` });
    const downloaded = createObjectURL.mock.calls[0][0] as Blob;
    expect(downloaded.type).toBe("application/pdf");
    expect(await downloaded.text()).toBe(pdf);
    expect(revokeObjectURL).toHaveBeenCalledWith("blob:case-report");
    expect(document.querySelector('a[download]')).toBeNull();
  });
});
