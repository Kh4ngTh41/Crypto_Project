# Tóm Tắt Vấn Đề Token Consumption — Heimdall SAST

Chi tiết tokens tại `/output/myscan`

## Bối cảnh

Heimdall là công cụ SAST (Static Application Security Testing) chạy bằng LLM, quét source code tìm lỗ hổng bảo mật thông qua pipeline 5 agent. Trong quá trình thử nghiệm nội bộ, chúng tôi quét thử một repo Python nhỏ để kiểm tra hoạt động của tool.

### Workflow

Heimdall quét repo qua 5 phase, điều phối bởi Orchestrator (orchestrator.py):
- 1. Setup — gitnexus analyze index repo thành knowledge graph → start MCP server, load 4 tools (context, query, impact, cypher) vào ToolRegistry
- 2. ScoutAgent — chạy 1 lần/repo: deep agent explore source → emit threat model (prose) → structurer LLM parse ra JSON (assets, entrypoints, focus_areas) → narrow files cần scan theo focus areas + callee expansion qua cypher
- 3. DetectionAgent — per-file: đọc source code → 1 LLM call with_structured_output → trả List[VulnerabilityDetail] (type, cwe, location, code_segment). Không gọi GitNexus.
- 4. MakeCallPathAgent — per-vuln: deep agent + 4 GitNexus tools trace ngược từ sink → entry point → trả CallPath (list FunctionInfo). Normalize từng function qua context tool để chống hallucination
- 5. VerifyAgent — per-vuln: gọi context programmatic (không qua LLM) để expand callees → LLM prune irrelevant → LLM classify TP/FP → nếu TP, LLM sinh dataflow diagram
- 6. ReportAgent — per-TP-finding: deep agent + context tool → LLM sinh explanation, CVSS vector, entry points → Python tính CVSS score → ghi findings.jsonl (stream) → cuối scan ghi report.json/report.md

**Đặc tính repo test:**

- Repo: `Crypto_Project` — ứng dụng Flask về cryptography (generate key, encrypt, sign transaction)
- Quy mô: 5 file Python, 652 dòng code
- Ngôn ngữ: Python
- Số vuln phát hiện: 2 (1 High Path Traversal, 1 Medium AES-CBC)

**Lý do lập báo cáo:**

Sau khi quét xong, em kiểm tra `report.json` và phát hiện tổng token tiêu thụ lên tới **10,646,950 tokens** cho một repo chỉ 652 dòng — tương đương ~16,300 tokens/dòng code. Con số này bất hợp lý so với quy mô repo. Báo cáo này phân tích nguyên nhân và đề xuất hướng khắc phục.

## Token breakdown theo agent (số liệu thực tế từ report.json)

| Agent | Input tokens | Output tokens | % total input |
|---|---|---|---|
| ScoutAgent | 207,279 | 12,013 | 2.0% |
| DetectionAgent | 2,505 | 3,751 | 0.02% |
| MakeCallPathAgent | 10,254,796 | 39,634 | 97.0% |
| VerifyAgent | 14,080 | 17,659 | 0.13% |
| ReportAgent | 90,863 | 4,370 | 0.86% |
| Total | 10,569,523 | 77,427 | 100% |

MakeCallPathAgent (MCPA) alone chiếm 97% tổng token. Các agent khác tiêu thụ mức hợp lý.

## Bảng tóm tắt 8 lỗi

| # | Lỗi | File:Dòng | Fix đề xuất |
|---|---|---|---|
| 1 | Đặt giới hạn quá cao cho turn LLM — `recursion_limit=1000` | `deepagents/graph.py:297` + `call_path_agent.py:168-175` | `.with_config({"recursion_limit": n})` - cần nghiên cứu để đề xuất `n` hợp lí |
| 2 | Token growth bậc hai O(N²) — message history accumulate toàn bộ tool results, mỗi turn LLM đọc lại tất cả history cũ | `call_path_agent.py:451-453` | Phải có cơ chế quản lí context cho agent(cơ bản: sliding windows hoặc có thể nghiên cứu vector db-dùng long/short term memory - retrive khi cần thiết) |
| 3 | Threat model context gửi lại mỗi call — ~10,000 tokens prepend vào mỗi user message thay vì gửi 1 lần | `call_path_agent.py:434-436` | Thiết kế Agent Communication |
| 4 | Không có context window management — `SummarizationMiddleware` có sẵn trong deepagents nhưng Heimdall không enable | `call_path_agent.py:168-175` | thiết kế cơ chế `/compact` |
| 5 | MCPA chạy per-vuln, không batch — 2 vuln cùng trace đến 1 entry point nhưng mỗi vuln trace độc lập, gọi tool trùng lặp | `call_path_agent.py:387-393` | Cache tool results chung cho các vuln cùng file |

> Lỗi #1 và #2 là nguyên nhân chính, chiếm phần lớn token waste. Các lỗi còn lại cộng dồn làm trầm trọng thêm.
