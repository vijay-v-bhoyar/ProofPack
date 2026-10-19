"""Validate planning artifacts only; does not test or approve the application."""
import copy
import csv
import hashlib
import json
import re
from datetime import datetime, timezone
from importlib.metadata import version
from pathlib import Path

import jsonschema
import yaml

ROOT = Path(__file__).resolve().parents[2]
checks = []


def check(name, condition, detail):
    checks.append({"name": name, "status": "PASS" if condition else "FAIL", "detail": detail})


def read(path):
    return (ROOT / path).read_text(encoding="utf-8-sig")


ledger = json.loads(read("evidence/index.json"))
schema = json.loads(read("docs/contracts/evidence.schema.json"))
jsonschema.Draft202012Validator.check_schema(schema)
validator = jsonschema.Draft202012Validator(schema, format_checker=jsonschema.FormatChecker())
errors = [error.message for error in validator.iter_errors(ledger)]
check("Evidence schema", not errors, errors or "Planned ledger conforms to Draft 2020-12.")
negative = copy.deepcopy(ledger)
negative["records"][0]["status"] = "PASS"
check("Reject unsupported PASS", bool(list(validator.iter_errors(negative))),
      "A status-only PASS with missing runtime proof must fail validation.")
check("Honest release state", ledger["release_decision"] == "NO_GO"
      and all(r["status"] in ("NOT_RUN", "BLOCKED") for r in ledger["records"]),
      "Product evidence remains unexecuted; documentation cannot authorize beta.")

backlog = read("BACKLOG.md")
tasks = []
for match in re.finditer(r"^\| (PP\d{2}) \| ([^|]+) \| ([^|]+) \| ([^|]+) \|$", backlog, re.M):
    ident, title, deps, hours = (part.strip() for part in match.groups())
    section = re.search(r"^## " + ident + r" .*?(?=^## PP|\Z)", backlog, re.M | re.S).group()
    acceptance = re.search(r"Acceptance: (.*?) verified by (.*?); evidence (.*?)\. Owner:", section)
    tasks.append({"id": ident, "title": title, "depends_on": re.findall(r"PP\d{2}", deps),
                  "requirements": re.findall(r"R\d{2}", acceptance[1]),
                  "tests": re.findall(r"T\d{2}", acceptance[2]),
                  "evidence": re.findall(r"E\d{2}", acceptance[3]), "effort_hours": hours})
controls = yaml.safe_load(read("docs/controls.yaml"))
trace = read("PRD.md").split("## Requirement traceability", 1)[1]
rows = []
for line in trace.splitlines():
    columns = [part.strip() for part in line.strip().strip("|").split("|")]
    if len(columns) == 6 and re.fullmatch(r"R\d{2}", columns[0]):
        rows.append(dict(zip(("requirement_id", "feature", "task_ids", "test_ids", "evidence_ids", "status"), columns)))
task_ids = {t["id"] for t in tasks}
req_ids = set(re.findall(r"^\| (R\d{2}) \|", read("PRD.md"), re.M))
test_ids = set(re.findall(r"^\| (T\d{2}) \|", read("docs/TEST-PLAN.md"), re.M))
evidence_ids = {e["id"] for e in ledger["records"]}
check("Inventory counts", (len(tasks), len(task_ids), len(req_ids), len(test_ids), len(evidence_ids), len(ledger["records"]))
      == (18, 18, 20, 58, 16, 16), "Expected 18 tasks, 20 requirements, 58 planned tests and 16 evidence records.")
refs_ok = all(set(t["depends_on"]) <= task_ids and set(t["requirements"]) <= req_ids
              and set(t["tests"]) <= test_ids and set(t["evidence"]) <= evidence_ids for t in tasks)
check("Backlog references", refs_ok, "Dependencies and requirement/test/evidence references resolve.")
remaining = {t["id"]: set(t["depends_on"]) for t in tasks}
ordered = []
while remaining:
    ready = [key for key, deps in remaining.items() if deps <= set(ordered)]
    if not ready:
        break
    for key in ready:
        ordered.append(key)
        del remaining[key]
check("Acyclic dependency graph", not remaining, ordered if not remaining else list(remaining))
trace_ok = len(rows) == len(req_ids) and {r["requirement_id"] for r in rows} == req_ids
trace_ok = trace_ok and all(set(r["task_ids"].split()) <= task_ids
                           and set(r["test_ids"].split()) <= test_ids
                           and set(r["evidence_ids"].split()) <= evidence_ids
                           and r["status"] == "NOT_RUN" for r in rows)
check("Requirement traceability", trace_ok, "Every product requirement maps to planned tasks, tests and evidence.")
task_map = {task["id"]: task for task in tasks}
check("Trace task ownership", all(r["requirement_id"] in task_map[t]["requirements"]
                                  for r in rows for t in r["task_ids"].split()),
      "Every traced task includes that requirement in its acceptance metadata.")
check("Evidence requirement bindings", all(set(e["requirements"]) ==
      {r["requirement_id"] for r in rows if e["id"] in r["evidence_ids"].split()}
      for e in ledger["records"]), "Ledger bindings match canonical requirement traceability.")
ranges = [re.search(r"(\d+)-(\d+)", t["effort_hours"]).groups() for t in tasks]
total = tuple(sum(int(pair[index]) for pair in ranges) for index in (0, 1))
check("Effort consistency", total == (124, 194) and "124–194" in read("IMPLEMENTATION-PLAN.md"),
      "Canonical task estimates total 124–194 hours including optional COOL work.")
check("Test coverage inventory", set().union(*(set(t["tests"]) for t in tasks)) == test_ids,
      "Every planned test has a backlog owner task; this does not mean tests ran.")
check("Five feature specifications", set(re.findall(r"^## (F\d) ", read("docs/FEATURE-SPECS.md"), re.M))
      == {"F1", "F2", "F3", "F4", "F5"}, "All five features have specifications.")
check("Confirmed beta boundary", controls["deployment"]["organization_count"] == 1
      and controls["deployment"]["spending_limit_usd"] is None
      and not controls["deployment"]["spending_authorized"]
      and not controls["deployment"]["external_beta_authorized"],
      "One business; no invented spending ceiling or authorization.")
check("Bounded proposed controls", controls["planner"]["max_corrective_requests"] == 2
      and controls["capture"]["max_observation_age_ms"] <= controls["capture"]["capture_permit_ttl_ms"]
      and controls["capture"]["stable_observation_count"] >= 3
      and controls["planner"]["max_model_requests_per_inspection"] == 2
      and controls["planner"]["max_concurrent_planner_calls_per_station"] == 1
      and controls["capture"]["observation_requests_per_second_per_station"] >= controls["capture"]["analyzed_frames_per_second"]
      and controls["capture"]["control_requests_per_second_per_station"] >= 2 * controls["capture"]["analyzed_frames_per_second"]
      and controls["planner"]["max_input_tokens"] == 4096
      and controls["planner"]["deployment_model_requests_limit"] is None,
      "Structural control relationships only; timing and safety require runtime validation.")

markdown = sorted(list(ROOT.glob("*.md")) + list((ROOT / "docs").rglob("*.md")))
broken = []
link_count = 0
receipt = ROOT / "evidence/documentation-validation.json"
for path in markdown:
    text = path.read_text(encoding="utf-8-sig")
    for target in re.findall(r"\[[^\]]*\]\(([^)]+)\)", text):
        if re.match(r"[a-zA-Z]+:", target) or target.startswith("#"):
            continue
        target = target.strip("<>").split("#")[0]
        link_count += 1
        dest = (path.parent / target).resolve()
        if not dest.exists() and dest != receipt:
            broken.append(str(path.relative_to(ROOT)) + " -> " + target)
check("Local documentation links", not broken, broken or f"{link_count} local links resolve; receipt is created by this run.")

retired = ["outputs/idea-review-hardware-kit-inspection.md", "outputs/moat-review-hardware-kit-inspection.md",
           "outputs/idea-add-moat-hardware-kit-inspection.md", "docs/backlog.yaml",
           "docs/traceability.csv", "docs/COGNITIVE-DEMANDS.csv"]
check("Superseded files removed", all(not (ROOT / name).exists() for name in retired),
      "Earlier iterations and duplicate planning representations are absent.")
check("No obsolete document references", all(not any(name in path.read_text(encoding="utf-8-sig")
      for name in retired) for path in markdown), "Retained Markdown references only current document owners.")
check("Missing reviews remain explicit", "NOT_RUN" in read("docs/SECURITY-PRIVACY.md")
      and "NOT_INITIALIZED" in read("IMPLEMENTATION-PLAN.md"),
      "Missing AI Red Team findings and product-loop receipts are not converted into executed evidence.")
personas_text = read("docs/PERSONAS-OPERATIONS.md")
personas = set(re.findall(r"^## (P0[1-9]) —", personas_text, re.M))
persona_steps = set()
for match in re.finditer(r"^## (P0[1-9]) —.*?(?=^## |\Z)", personas_text, re.M | re.S):
    for step in re.findall(r"^\| (\d+)\. ", match.group(), re.M):
        persona_steps.add((match[1], f"{int(step):02d}"))
persona_tables_ok = True
for match in re.finditer(r"^## (P0[1-9]) —.*?(?=^## |\Z)", personas_text, re.M | re.S):
    lines = match.group().splitlines()
    expected = [int(n) for n in re.findall(r"^\| (\d+)\. ", match.group(), re.M)]
    header = next((i for i, line in enumerate(lines) if line == "| Step | Operation | Result or handoff |"), None)
    actual = []
    if header is not None:
        for line in lines[header + 2:]:
            m = re.match(r"^\| (\d+)\. ", line)
            if not m:
                break
            actual.append(int(m[1]))
    persona_tables_ok &= actual == expected and actual == list(range(1, len(expected) + 1))
check("Persona workflow table continuity", persona_tables_ok,
      "All numbered operations render in one contiguous correctly headed table per persona.")

workflow_text = read("docs/WORKFLOW-COVERAGE.md")
workflows = {}
step_rows = []
for line in workflow_text.splitlines():
    cells = [c.strip() for c in line.strip().strip("|").split("|")]
    if len(cells) == 6 and re.match(r"W\d{2} —", cells[0]):
        wid = cells[0].split(" ")[0]
        workflows[wid] = {"personas": set(cells[2].split()), "tests": set(cells[3].split()),
                          "evidence": set(cells[4].split()), "status": cells[5]}
    if len(cells) == 3 and re.fullmatch(r"P0[1-9]", cells[0]) and re.fullmatch(r"\d{2}", cells[1]):
        step_rows.append((cells[0], cells[1], cells[2].split()))
check("Persona and workflow inventory", len(personas) == 9 and len(persona_steps) == 78
      and len(workflows) == 26, "Nine defined personas, 78 operations and 26 workflow contracts.")
check("Every persona operation mapped", len(step_rows) == 78
      and {(p, step) for p, step, _ in step_rows} == persona_steps
      and all(ids and all(w in workflows and p in workflows[w]["personas"] for w in ids)
              for p, step, ids in step_rows), "Every actual numbered operation has a valid responsibility/workflow mapping.")
check("Workflow references and test coverage", all(w["personas"] <= personas and w["tests"]
      and w["tests"] <= test_ids and w["evidence"] and w["evidence"] <= evidence_ids
      and w["status"] == "NOT_RUN" for w in workflows.values())
      and set().union(*(w["tests"] for w in workflows.values())) == test_ids,
      "Every workflow has valid personas/tests/evidence; all 58 tests are covered, none reported executed.")

# A reusable study seed must track the canonical operations without prefilled results.
with (ROOT / "docs/templates/PERSONA-OPERATION-EVIDENCE.csv").open(
        encoding="utf-8-sig", newline="") as seed_file:
    seed_reader = csv.DictReader(seed_file)
    seed_fields = seed_reader.fieldnames
    seed_rows = list(seed_reader)
expected_seed_fields = [
    "persona_id", "operation_step", "operation_label", "workflow_ids", "technical_scope_ids",
    "session_id", "scenario_id", "condition_and_applicability", "exact_subject_and_permissions",
    "task_result", "task_evidence_and_assessor", "mechanism_result", "mechanism_evidence_and_assessor",
    "human_result", "human_evidence_and_assessor", "technical_result", "technical_evidence_and_assessor",
    "accepting_person_and_acknowledgment", "remaining_duties_and_next_action"]
operation_labels = {}
for section in re.finditer(r"^## (P0[1-9]) —.*?(?=^## |\Z)", personas_text, re.M | re.S):
    for operation in re.finditer(r"^\| (\d+)\. (.*?) \|", section.group(), re.M):
        operation_labels[(section[1], f"{int(operation[1]):02d}")] = operation[2]
mapped_steps = {(p, step): set(ids) for p, step, ids in step_rows}
seed_problems = []
seen_seed_steps = set()
for number, row in enumerate(seed_rows, 2):
    key = (row.get("persona_id"), row.get("operation_step"))
    ids = set((row.get("workflow_ids") or "").split())
    expected_ids = mapped_steps.get(key, set())
    expected_tests = set().union(*(workflows[w]["tests"] for w in expected_ids))
    valid = (None not in row and all(v is not None for v in row.values())
             and key in persona_steps and key not in seen_seed_steps
             and row.get("operation_label") == operation_labels.get(key)
             and ids == expected_ids
             and set((row.get("technical_scope_ids") or "").split()) == expected_tests
             and row.get("condition_and_applicability") == "NOT_ASSESSED")
    for field in expected_seed_fields[5:]:
        expected = "NOT_ASSESSED" if field == "condition_and_applicability" else (
            "NOT_RUN" if field in {"task_result", "mechanism_result", "human_result", "technical_result"} else "")
        valid &= row.get(field) == expected
    if not valid:
        seed_problems.append(f"row {number}: inconsistent operation, mapping or blank-result contract")
    seen_seed_steps.add(key)
check("Persona operation study seed", seed_fields == expected_seed_fields
      and len(seed_rows) == len(persona_steps) and seen_seed_steps == persona_steps and not seed_problems,
      seed_problems or "All 78 operations match canonical labels/workflows/tests; four result layers remain NOT_RUN with no invented evidence or accountable person.")
planned_coverage_ok = True
for record in ledger["records"]:
    expected_w = {wid for wid, w in workflows.items() if record["id"] in w["evidence"]}
    expected_p = set().union(*(workflows[wid]["personas"] for wid in expected_w))
    available_t = set().union(*(workflows[wid]["tests"] for wid in expected_w))
    planned_coverage_ok &= (set(record["planned_workflow_ids"]) == expected_w
                            and set(record["planned_persona_ids"]) == expected_p
                            and bool(record["planned_test_ids"])
                            and set(record["planned_test_ids"]) <= available_t
                            and record["test_results"] == []
                            and record["coverage_manifest_sha256"] is None)
check("Planned versus actual evidence coverage", planned_coverage_ok
      and set().union(*(set(e["planned_test_ids"]) for e in ledger["records"])) == test_ids,
      "Evidence plans bind valid workflows/personas/tests; actual results/manifests remain absent.")
check("Boundary contracts documented", all(term in read("docs/STATE-DATA-API.md") for term in
      ["RuntimeControlHead", "DataAuthorityHead", "SessionRecord", "AllocationHead", "/invitations",
       "/owner-transfers", "/stations/{id}/release", "/calibrations/{id}/approve",
       "/assets/{id}/download", "/jobs/{id}/cancel", "/admin/enable-inspection"])
      and "route names are not yet specified" not in personas_text,
      "Previously missing lifecycle endpoints and authority heads have explicit contracts.")

# Verify user-facing traceability independently of technical case inventory.
# These checks establish document structure, never participant or product results.
adoption_text = read("docs/USER-NEEDS-ADOPTION.md")
def table_rows(text):
    return [[cell.strip() for cell in line.strip().strip("|").split("|")]
            for line in text.splitlines() if line.startswith("| ")]

def adoption_gate_contract(text):
    """Check one scoped decision table; never infer that its evidence is true."""
    names = {"User understanding", "Product value", "Experience", "Technical assurance",
             "Demonstration", "Adoption", "Publication"}
    heading = "## Seven gates for the first supervised external pilot"
    if text.count(heading) != 1:
        return False
    section = text.split(heading, 1)[1].split("\n## ", 1)[0]
    rows = [row for row in table_rows(section) if row[0] in names]
    all_rows = [row for row in table_rows(text) if row[0] in names]
    return (len(rows) == len(names) and len(all_rows) == len(names)
            and {row[0] for row in rows} == names
            and all(len(row) == 4 and all(row) and row[1] in
                    {"READY", "CONDITIONAL", "BLOCKED", "UNKNOWN"} for row in rows))


check("Single scoped adoption gate decision", adoption_gate_contract(adoption_text),
      "One complete external-pilot gate table, unique gate identities, valid decisions and explicit evidence/duties; rehearsal is a separate scope.")

adoption_rows = table_rows(adoption_text)
child_definitions = []
for source_text in (adoption_text, read("docs/TEST-PLAN.md")):
    for row in table_rows(source_text):
        match = re.match(r"^(A\d{2}-[A-Z]+\d+)(?:$|[; /])", row[0])
        if match:
            child_definitions.append(match[1])
check("Canonical child scenario identity", len(child_definitions) == len(set(child_definitions)),
      "Child scenarios have one canonical definition across adoption and test-plan tables; references may repeat.")


def affected_group_contract(persona_document, session_document, available_scenarios):
    """Check planned non-user coverage, not real-world applicability or acceptance."""
    group_rows = [row for row in table_rows(persona_document)
                  if re.fullmatch(r"AP\d{2}", row[0])]
    study_rows = [row for row in table_rows(session_document)
                  if re.fullmatch(r"AP\d{2}", row[0])]
    expected = {"AP01": "A04-AP1", "AP02": "A05-AP1",
                "AP03": "A01-AP1", "AP04": "A07-P1"}
    if (len(group_rows) != 4 or len(study_rows) != 4
            or {row[0] for row in group_rows} != expected.keys()
            or {row[0] for row in study_rows} != expected.keys()):
        return False
    for row in group_rows:
        if (len(row) != 6 or not all(row) or row[4] != expected[row[0]]
                or row[4] not in available_scenarios or row[5] != "NOT_RUN"
                or not set(row[2].split()) <= personas
                or not set(row[3].split()) <= workflows.keys()):
            return False
    return all(row == [row[0], expected[row[0]], "NOT_ASSESSED",
                       "NOT_RUN", "NOT_RUN", "NOT_RUN", "NOT_RUN",
                       "Not collected", "Not assigned"] for row in study_rows)


session_text = read("docs/templates/BETA-SESSION-RECORD.md")
check("Affected non-user journey coverage",
      affected_group_contract(personas_text, session_text, set(child_definitions)),
      "Four existing groups resolve duties/workflows and canonical scenarios; study applicability, independent result layers and accepting people remain unassessed.")
missing_group_text = "\n".join(line for line in session_text.splitlines()
                               if not line.startswith("| AP04 |"))
false_pass_text = session_text.replace("| AP01 | A04-AP1 | NOT_ASSESSED | NOT_RUN |",
                                       "| AP01 | A04-AP1 | NOT_ASSESSED | PASS |", 1)
check("Reject omitted group and invented affected-person PASS",
      not affected_group_contract(personas_text, missing_group_text, set(child_definitions))
      and not affected_group_contract(personas_text, false_pass_text, set(child_definitions))
      and not affected_group_contract(personas_text, session_text, set(child_definitions) - {"A05-AP1"}),
      "Negative controls reject missing coverage, unsupported study PASS and unresolved scenario references.")
findings = {row[0]: row for row in adoption_rows if re.fullmatch(r"U\d{2}", row[0])}
needs = {row[0].split(" / ")[0]: row for row in adoption_rows
         if re.fullmatch(r"N\d{2} / U\d{2}( U\d{2})*", row[0])}
scenarios = {row[0]: row for row in adoption_rows if re.fullmatch(r"A\d{2}", row[0])}
finding_types = {"OBSERVED", "SELF_REPORTED", "THIRD_PARTY_REPORTED", "HYPOTHESIS", "CONTRADICTED", "UNKNOWN"}
check("Adoption finding provenance", bool(findings)
      and all(len(row) == 5 and row[1] in finding_types and all(row[2:]) for row in findings.values()),
      "Findings retain classified source/context, applicability and next validation; no human evidence inferred.")
check("Need and scenario traceability", len(needs) == 9 and len(scenarios) == 9
      and all(len(row) == 4 and set(re.findall(r"U\d{2}", row[0])) <= findings.keys()
              and set(re.findall(r"W\d{2}", row[2])) <= workflows.keys()
              and set(re.findall(r"R\d{2}", row[2])) <= req_ids
              and bool(re.findall(r"A\d{2}", row[3]))
              and set(re.findall(r"A\d{2}", row[3])) <= scenarios.keys() for row in needs.values())
      and all(len(row) == 5 and bool(re.findall(r"P\d{2}", row[1]))
              and set(re.findall(r"P\d{2}", row[1])) <= personas
              and bool(re.findall(r"N\d{2}", row[1]))
              and set(re.findall(r"N\d{2}", row[1])) <= needs.keys()
              and bool(re.findall(r"T\d{2}", row[3]))
              and set(re.findall(r"T\d{2}", row[3])) <= test_ids
              and row[4] == "NOT_RUN" for row in scenarios.values()),
      "Nine needs resolve findings/workflows/requirements/scenarios; nine planned scenarios resolve personas/needs/tests.")
entry_section = personas_text.split("## Journey entry, completion and adoption evidence", 1)[-1].split("## Affected people", 1)[0]
entry_rows = [row for row in table_rows(entry_section) if re.fullmatch(r"P0[1-9]", row[0])]
check("Persona evaluation and exit coverage", len(entry_rows) == len(personas)
      and {row[0] for row in entry_rows} == personas
      and all(len(row) == 4 and all(row[1:]) and bool(re.findall(r"A\d{2}", row[3]))
              and set(re.findall(r"A\d{2}", row[3])) <= scenarios.keys() for row in entry_rows),
      "Each persona has entry, completion/safe exit, evaluation scenarios and an unresolved research obligation.")
check("Final workspace hygiene", not (ROOT / ".audit-temp.py").exists()
      and not (ROOT / ".audit-temp.json").exists(), "No temporary audit construction files remain.")

gap_section = personas_text.split("## Persona implementation and validation gaps", 1)[-1].split("### Access and experience variants", 1)[0]
gap_rows = [row for row in table_rows(gap_section) if re.fullmatch(r"P0[1-9]", row[0])]
check("Persona implementation gaps and evidence", len(gap_rows) == len(personas)
      and {row[0] for row in gap_rows} == personas
      and all(len(row) == 4 and all(row[1:]) and bool(re.findall(r"A\d{2}", row[3]))
              and set(re.findall(r"A\d{2}", row[3])) <= scenarios.keys() for row in gap_rows),
      "Every persona distinguishes local support, remaining work and actual completion evidence.")

artifacts = sorted(set(markdown + list((ROOT / "docs").rglob("*.json"))
                       + list((ROOT / "docs").rglob("*.yaml")) + list((ROOT / "docs").rglob("*.csv"))
                       + [ROOT / "evidence/index.json", Path(__file__).resolve()]))
status = "PASS" if all(c["status"] == "PASS" for c in checks) else "FAIL"
report = {"scope": "documentation_structure_only", "status": status,
          "recorded_at": datetime.now(timezone.utc).isoformat(),
          "command": "python docs/contracts/validate_documentation.py",
          "exit_code": 0 if status == "PASS" else 1,
          "tools": {"PyYAML": version("PyYAML"), "jsonschema": version("jsonschema")},
          "checks": checks, "application_tests": "NOT_RUN", "beta_decision": "NO_GO",
          "limitations": ["No application, cloud, physical, user or performance testing was performed.",
                          "External link content is outside this structural validator.",
                          "Schema conformance cannot establish evidence authenticity or release approval."],
          "inputs": [{"path": str(p.relative_to(ROOT)).replace("\\", "/"),
                      "sha256": hashlib.sha256(p.read_bytes()).hexdigest()} for p in artifacts]}
receipt.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
print(json.dumps({"status": status, "checks": len(checks), "inputs": len(artifacts),
                  "failures": [c for c in checks if c["status"] == "FAIL"]}, indent=2))
raise SystemExit(report["exit_code"])
