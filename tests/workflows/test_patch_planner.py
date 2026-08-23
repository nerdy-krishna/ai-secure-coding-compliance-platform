import unittest

from app.core.schemas import FixResult, FixSuggestion, VulnerabilityFinding
from app.infrastructure.workflows.nodes.consolidate import build_validation_summary
from app.shared.lib.dependency_requirements import (
    build_dependency_inventory,
    validate_candidate_dependencies,
)
from app.shared.lib.finding_lineage_identity import (
    anchor_fingerprint,
    fix_candidate_id,
    patch_fingerprint,
    raw_finding_id,
)
from app.shared.lib.import_requirements import (
    build_static_import_inventory,
    validate_candidate_imports,
)
from app.shared.lib.patch_planner import (
    PatchPlanBudget,
    PatchPlanLimits,
    PatchValidationCheck,
    plan_file_patch,
    source_hash,
    validate_candidate_replacement,
)


SCAN_ID = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"


def candidate(
    source: str, original: str, replacement: str, line: int, index: int
) -> FixResult:
    snapshot = source_hash(source)
    raw = raw_finding_id(SCAN_ID, "planner-test", index)
    anchor = anchor_fingerprint(
        file_path="src/app.py",
        source_snapshot_hash=snapshot,
        line_number=line,
        original_snippet=original,
    )
    patch = patch_fingerprint(anchor=anchor, replacement_code=replacement)
    finding = VulnerabilityFinding(
        raw_finding_id=raw,
        source_snapshot_hash=snapshot,
        title="Unsafe operation",
        description="Unsafe operation",
        severity="High",
        line_number=line,
        remediation="Use the safe operation",
        confidence="High",
        references=[],
        file_path="src/app.py",
    )
    return FixResult(
        finding=finding,
        suggestion=FixSuggestion(
            description="Replace safely",
            original_snippet=original,
            code=replacement,
        ),
        candidate_id=fix_candidate_id(raw_id=raw, patch=patch),
        raw_finding_id=raw,
        source_snapshot_hash=snapshot,
        anchor_fingerprint=anchor,
        patch_fingerprint=patch,
        disposition="selected",
        validation_status="passed",
    )


class PatchPlannerTests(unittest.TestCase):
    def test_patch_size_policy_accepts_exact_hunk_and_expansion_boundaries(self):
        source = "danger()\n"
        item = candidate(source, "danger()", "safe()xxxxxx", 1, 0)
        limits = PatchPlanLimits(
            max_hunks_per_file=1,
            max_hunks_per_plan=1,
            max_replacement_expansion_bytes_per_file=4,
            max_replacement_expansion_bytes_per_plan=4,
            max_unified_diff_bytes_per_file=1_000,
            max_unified_diff_bytes_per_plan=1_000,
        )
        budget = PatchPlanBudget(limits)

        plan, decisions, patched = plan_file_patch(
            file_path="src/app.py",
            source=source,
            expected_source_hash=source_hash(source),
            candidates=[item],
            limits=limits,
            plan_budget=budget,
        )

        self.assertEqual(plan.status, "planned")
        self.assertEqual(decisions[0].status, "planned")
        self.assertEqual(patched, "safe()xxxxxx\n")
        self.assertEqual((budget.hunks, budget.replacement_expansion_bytes), (1, 4))
        size_check = next(
            check
            for check in plan.validation_checks
            if check.stage == "patch_size_policy"
        )
        self.assertEqual(size_check.status, "passed")

    def test_replacement_expansion_over_limit_fails_closed_without_diff(self):
        source = "danger()\n"
        item = candidate(source, "danger()", "safe()xxxxxx", 1, 0)
        limits = PatchPlanLimits(
            max_replacement_expansion_bytes_per_file=3,
        )

        plan, decisions, patched = plan_file_patch(
            file_path="src/app.py",
            source=source,
            expected_source_hash=source_hash(source),
            candidates=[item],
            limits=limits,
        )

        self.assertEqual((patched, plan.hunks, plan.unified_diff), (source, [], ""))
        self.assertEqual(plan.status, "manual_review_required")
        self.assertEqual(decisions[0].status, "conflict")
        self.assertIsNone(item.patch_hunk_id)
        size_check = next(
            check
            for check in plan.validation_checks
            if check.stage == "patch_size_policy"
        )
        self.assertEqual(size_check.status, "failed")
        self.assertIn("replacement expansion bytes", size_check.detail)

    def test_hunk_limit_rejects_whole_file_atomically(self):
        source = "one()\ntwo()\n"
        items = [
            candidate(source, "one()", "safe_one()", 1, 0),
            candidate(source, "two()", "safe_two()", 2, 1),
        ]

        plan, decisions, patched = plan_file_patch(
            file_path="src/app.py",
            source=source,
            expected_source_hash=source_hash(source),
            candidates=items,
            limits=PatchPlanLimits(max_hunks_per_file=1),
        )

        self.assertEqual((patched, plan.hunks, plan.unified_diff), (source, [], ""))
        self.assertEqual(plan.status, "manual_review_required")
        self.assertEqual({decision.status for decision in decisions}, {"conflict"})
        self.assertTrue(all(item.patch_hunk_id is None for item in items))

    def test_serialized_diff_byte_limit_accepts_boundary_and_rejects_overflow(self):
        source = "danger()\n"
        baseline, _, _ = plan_file_patch(
            file_path="src/app.py",
            source=source,
            expected_source_hash=source_hash(source),
            candidates=[candidate(source, "danger()", "safe()", 1, 0)],
        )
        diff_bytes = len(baseline.unified_diff.encode("utf-8"))

        accepted, _, accepted_output = plan_file_patch(
            file_path="src/app.py",
            source=source,
            expected_source_hash=source_hash(source),
            candidates=[candidate(source, "danger()", "safe()", 1, 1)],
            limits=PatchPlanLimits(max_unified_diff_bytes_per_file=diff_bytes),
        )
        rejected, decisions, rejected_output = plan_file_patch(
            file_path="src/app.py",
            source=source,
            expected_source_hash=source_hash(source),
            candidates=[candidate(source, "danger()", "safe()", 1, 2)],
            limits=PatchPlanLimits(max_unified_diff_bytes_per_file=diff_bytes - 1),
        )

        self.assertEqual(accepted_output, "safe()\n")
        self.assertEqual(len(accepted.unified_diff.encode("utf-8")), diff_bytes)
        self.assertEqual((rejected_output, rejected.unified_diff), (source, ""))
        self.assertEqual(rejected.status, "manual_review_required")
        self.assertEqual(decisions[0].status, "conflict")

    def test_scan_budget_rejects_later_file_without_growing_totals(self):
        source = "danger()\n"
        limits = PatchPlanLimits(
            max_hunks_per_plan=1,
            max_replacement_expansion_bytes_per_plan=1_000,
            max_unified_diff_bytes_per_plan=1_000,
        )
        budget = PatchPlanBudget(limits)
        first = candidate(source, "danger()", "safe()", 1, 0)
        second = candidate(source, "danger()", "safer()", 1, 1)
        second.finding.file_path = "src/other.py"

        first_plan, _, first_output = plan_file_patch(
            file_path="src/app.py",
            source=source,
            expected_source_hash=source_hash(source),
            candidates=[first],
            limits=limits,
            plan_budget=budget,
        )
        second_plan, second_decisions, second_output = plan_file_patch(
            file_path="src/other.py",
            source=source,
            expected_source_hash=source_hash(source),
            candidates=[second],
            limits=limits,
            plan_budget=budget,
        )

        self.assertEqual(first_plan.status, "planned")
        self.assertEqual(first_output, "safe()\n")
        self.assertEqual((second_output, second_plan.unified_diff), (source, ""))
        self.assertEqual(second_plan.status, "manual_review_required")
        self.assertEqual(second_decisions[0].status, "conflict")
        self.assertEqual(budget.hunks, 1)

    def test_scan_budget_checks_expansion_and_serialized_diff_dimensions(self):
        limits = PatchPlanLimits(
            max_hunks_per_plan=10,
            max_replacement_expansion_bytes_per_plan=4,
            max_unified_diff_bytes_per_plan=8,
        )
        budget = PatchPlanBudget(limits)
        budget.commit(
            hunks=1,
            replacement_expansion_bytes=4,
            unified_diff_bytes=8,
        )

        expansion_violation = budget.plan_violation(
            hunks=0,
            replacement_expansion_bytes=1,
            unified_diff_bytes=0,
        )
        diff_violation = budget.plan_violation(
            hunks=0,
            replacement_expansion_bytes=0,
            unified_diff_bytes=1,
        )

        self.assertIn("replacement expansion bytes", expansion_violation)
        self.assertIn("serialized unified-diff bytes", diff_violation)
        self.assertEqual(
            (
                budget.hunks,
                budget.replacement_expansion_bytes,
                budget.unified_diff_bytes,
            ),
            (1, 4, 8),
        )

    def test_repeated_snippet_uses_recorded_line_and_never_first_occurrence_guess(self):
        source = "danger()\nkeep()\ndanger()\n"
        item = candidate(source, "danger()", "safe()", 3, 0)
        plan, decisions, patched = plan_file_patch(
            file_path="src/app.py",
            source=source,
            expected_source_hash=source_hash(source),
            candidates=[item],
        )
        self.assertEqual(patched, "danger()\nkeep()\nsafe()\n")
        self.assertEqual(plan.hunks[0].resolved_range.start_line, 3)
        self.assertEqual(decisions[0].status, "planned")

    def test_repeated_snippet_with_line_drift_is_rejected_as_ambiguous(self):
        source = "danger()\nkeep()\ndanger()\n"
        item = candidate(source, "danger()", "safe()", 2, 0)
        plan, decisions, patched = plan_file_patch(
            file_path="src/app.py",
            source=source,
            expected_source_hash=source_hash(source),
            candidates=[item],
        )
        self.assertEqual((patched, plan.hunks), (source, []))
        self.assertEqual(decisions[0].status, "ambiguous")

    def test_unique_anchor_with_line_drift_is_corrected_deterministically(self):
        source = "keep()\ndanger()\n"
        item = candidate(source, "danger()", "safe()", 99, 0)
        plan, decisions, patched = plan_file_patch(
            file_path="src/app.py",
            source=source,
            expected_source_hash=source_hash(source),
            candidates=[item],
        )
        self.assertEqual(patched, "keep()\nsafe()\n")
        self.assertEqual(plan.hunks[0].resolved_range.start_line, 2)
        self.assertEqual(decisions[0].status, "planned")

    def test_preplanning_validation_uses_the_same_recorded_line_resolution(self):
        source = "danger()\nkeep()\ndanger()\n"
        item = candidate(source, "danger()", "safe()", 3, 0)
        decision = validate_candidate_replacement(
            candidate=item,
            file_path="src/app.py",
            source=source,
            expected_source_hash=source_hash(source),
            syntax_validator=lambda code, _path: code == "danger()\nkeep()\nsafe()\n",
        )
        self.assertEqual(decision.status, "planned")
        self.assertEqual(decision.resolved_range.start_line, 3)

    def test_transitive_overlap_is_one_manual_review_component(self):
        source = "abcdef\n"
        items = [
            candidate(source, "abc", "A", 1, 0),
            candidate(source, "cde", "C", 1, 1),
            candidate(source, "ef", "E", 1, 2),
        ]
        plan, decisions, patched = plan_file_patch(
            file_path="src/app.py",
            source=source,
            expected_source_hash=source_hash(source),
            candidates=items,
        )
        self.assertEqual(patched, source)
        self.assertEqual(len(plan.conflict_components), 1)
        self.assertEqual(len(plan.conflict_components[0]), 3)
        self.assertEqual({decision.status for decision in decisions}, {"conflict"})

    def test_non_overlapping_unicode_crlf_edits_apply_in_one_atomic_plan(self):
        source = "π = unsafe_a()\r\nvalue = unsafe_b()\r\n"
        items = [
            candidate(source, "unsafe_a()\n", "safe_a()\n", 1, 0),
            candidate(source, "unsafe_b()", "safe_b()", 2, 1),
        ]
        plan, _, patched = plan_file_patch(
            file_path="src/app.py",
            source=source,
            expected_source_hash=source_hash(source),
            candidates=items,
        )
        self.assertEqual(patched, "π = safe_a()\r\nvalue = safe_b()\r\n")
        self.assertGreater(plan.hunks[0].resolved_range.start_byte, 0)
        replay_plan, _, replayed = plan_file_patch(
            file_path="src/app.py",
            source=source,
            expected_source_hash=source_hash(source),
            candidates=items,
        )
        self.assertEqual((replay_plan, replayed), (plan, patched))

    def test_exact_duplicate_resolved_edit_collapses(self):
        source = "danger()\n"
        items = [
            candidate(source, "danger()", "safe()", 1, 0),
            candidate(source, "danger()", "safe()", 1, 1),
        ]
        plan, decisions, patched = plan_file_patch(
            file_path="src/app.py",
            source=source,
            expected_source_hash=source_hash(source),
            candidates=items,
        )
        self.assertEqual(patched, "safe()\n")
        self.assertEqual(len(plan.hunks), 1)
        self.assertEqual(sorted(d.status for d in decisions), ["duplicate", "planned"])

    def test_required_python_import_is_an_explicit_candidate_linked_hunk(self):
        source = '"""module"""\n\ndef run():\n    return danger()\n'
        item = candidate(source, "danger()", "safe()", 4, 0)
        item.language = "python"
        item.required_imports = ["from security import safe"]
        dependency_inventory = build_dependency_inventory({})
        import_inventory = build_static_import_inventory(
            {
                "src/app.py": source,
                "src/security.py": "def safe():\n    return True\n",
            },
            dependency_inventory,
        )
        plan, decisions, patched = plan_file_patch(
            file_path="src/app.py",
            source=source,
            expected_source_hash=source_hash(source),
            candidates=[item],
            import_validator=lambda value: validate_candidate_imports(
                value, import_inventory
            ),
        )
        self.assertEqual(decisions[0].status, "planned")
        self.assertEqual(len(plan.hunks), 2)
        import_hunk = next(hunk for hunk in plan.hunks if not hunk.original_text)
        self.assertEqual(import_hunk.candidate_ids, [item.candidate_id])
        self.assertIn('"""module"""\nfrom security import safe\n', patched)
        import_check = next(
            check
            for check in plan.validation_checks
            if check.stage == "import_requirements"
        )
        self.assertEqual(import_check.status, "passed")
        self.assertIn("src/security.py", import_check.detail)

    def test_required_import_without_static_resolver_fails_closed(self):
        source = "danger()\n"
        item = candidate(source, "danger()", "safe()", 1, 0)
        item.language = "python"
        item.required_imports = ["from security import safe"]
        plan, decisions, patched = plan_file_patch(
            file_path="src/app.py",
            source=source,
            expected_source_hash=source_hash(source),
            candidates=[item],
        )
        self.assertEqual(patched, source)
        self.assertEqual(decisions[0].status, "conflict")
        self.assertEqual(plan.validation_checks[0].status, "not_run")

    def test_missing_local_import_name_blocks_patch(self):
        source = "danger()\n"
        item = candidate(source, "danger()", "safe()", 1, 0)
        item.language = "python"
        item.required_imports = ["from security import safe"]
        dependency_inventory = build_dependency_inventory({})
        import_inventory = build_static_import_inventory(
            {"src/app.py": source, "src/security.py": "def other():\n    pass\n"},
            dependency_inventory,
        )
        plan, decisions, patched = plan_file_patch(
            file_path="src/app.py",
            source=source,
            expected_source_hash=source_hash(source),
            candidates=[item],
            import_validator=lambda value: validate_candidate_imports(
                value, import_inventory
            ),
        )
        self.assertEqual(patched, source)
        self.assertEqual(decisions[0].status, "conflict")
        self.assertIn("not exported", decisions[0].reason)

    def test_unreported_import_inside_replacement_is_still_validated(self):
        source = "danger()\n"
        item = candidate(
            source,
            "danger()",
            "import undeclared_security\nundeclared_security.safe()",
            1,
            0,
        )
        item.language = "python"
        dependency_inventory = build_dependency_inventory({})
        import_inventory = build_static_import_inventory(
            {"src/app.py": source}, dependency_inventory
        )
        plan, decisions, patched = plan_file_patch(
            file_path="src/app.py",
            source=source,
            expected_source_hash=source_hash(source),
            candidates=[item],
            import_validator=lambda value: validate_candidate_imports(
                value, import_inventory
            ),
        )
        self.assertEqual(patched, source)
        self.assertEqual(decisions[0].status, "conflict")
        self.assertIn(
            "no local, standard-library, or manifest evidence", decisions[0].reason
        )

    def test_unreported_bare_symbol_without_import_is_blocking(self):
        source = "def run(value):\n    return danger(value)\n"
        item = candidate(source, "danger(value)", "sanitize(value)", 2, 0)
        item.language = "python"
        inventory = build_static_import_inventory(
            {"src/app.py": source}, build_dependency_inventory({})
        )
        plan, decisions, patched = plan_file_patch(
            file_path="src/app.py",
            source=source,
            expected_source_hash=source_hash(source),
            candidates=[item],
            import_validator=lambda value: validate_candidate_imports(value, inventory),
        )
        self.assertEqual(patched, source)
        self.assertEqual(decisions[0].status, "conflict")
        check = next(
            value
            for value in plan.validation_checks
            if value.stage == "import_requirements"
        )
        self.assertEqual(check.status, "failed")
        self.assertIn("new bare symbol", check.detail)

    def test_new_bare_symbol_declared_in_target_file_is_proven(self):
        source = (
            "def sanitize(value):\n    return value\n\n"
            "def run(value):\n    return danger(value)\n"
        )
        item = candidate(source, "danger(value)", "sanitize(value)", 5, 0)
        item.language = "python"
        inventory = build_static_import_inventory(
            {"src/app.py": source}, build_dependency_inventory({})
        )
        _, decisions, patched = plan_file_patch(
            file_path="src/app.py",
            source=source,
            expected_source_hash=source_hash(source),
            candidates=[item],
            import_validator=lambda value: validate_candidate_imports(value, inventory),
        )
        self.assertEqual(decisions[0].status, "planned")
        self.assertIn("return sanitize(value)", patched)

    def test_dependency_requirement_blocks_source_patch_until_manifest_hunk_exists(
        self,
    ):
        source = "danger()\n"
        item = candidate(source, "danger()", "safe()", 1, 0)
        item.language = "python"
        item.required_dependencies = ["secure-db>=2"]
        plan, decisions, patched = plan_file_patch(
            file_path="src/app.py",
            source=source,
            expected_source_hash=source_hash(source),
            candidates=[item],
        )
        self.assertEqual(patched, source)
        self.assertEqual(decisions[0].status, "conflict")
        self.assertEqual(plan.status, "manual_review_required")
        self.assertEqual(plan.requirements[0].required_dependencies, ["secure-db>=2"])
        dependency_check = next(
            check
            for check in plan.validation_checks
            if check.stage == "dependency_requirements"
        )
        self.assertEqual(dependency_check.status, "not_run")

    def test_compatible_existing_python_dependency_allows_source_patch(self):
        source = "danger()\n"
        item = candidate(source, "danger()", "safe()", 1, 0)
        item.language = "python"
        item.required_dependencies = ["secure-db>=2"]
        inventory = build_dependency_inventory(
            {
                "pyproject.toml": (
                    "[project]\n"
                    'dependencies = ["secure-db>=2,<3", "other-package==1"]\n'
                )
            }
        )
        plan, decisions, patched = plan_file_patch(
            file_path="src/app.py",
            source=source,
            expected_source_hash=source_hash(source),
            candidates=[item],
            dependency_validator=lambda value: validate_candidate_dependencies(
                value, inventory
            ),
        )
        self.assertEqual(patched, "safe()\n")
        self.assertEqual(decisions[0].status, "planned")
        dependency_check = next(
            check
            for check in plan.validation_checks
            if check.stage == "dependency_requirements"
        )
        self.assertEqual(dependency_check.status, "passed")
        self.assertIn("pyproject.toml", dependency_check.detail)

    def test_dependency_version_mismatch_remains_manual_review(self):
        source = "danger()\n"
        item = candidate(source, "danger()", "safe()", 1, 0)
        item.language = "python"
        item.required_dependencies = ["secure-db>=2"]
        inventory = build_dependency_inventory(
            {"requirements.txt": "secure-db>=1,<2\n"}
        )
        plan, decisions, patched = plan_file_patch(
            file_path="src/app.py",
            source=source,
            expected_source_hash=source_hash(source),
            candidates=[item],
            dependency_validator=lambda value: validate_candidate_dependencies(
                value, inventory
            ),
        )
        self.assertEqual(patched, source)
        self.assertEqual(decisions[0].status, "conflict")
        self.assertEqual(plan.validation_checks[0].status, "failed")
        self.assertIn("version compatibility unproven", decisions[0].reason)

    def test_npm_and_go_manifests_are_inventory_evidence(self):
        source = "danger()\n"
        npm_item = candidate(source, "danger()", "safe()", 1, 0)
        npm_item.language = "typescript"
        npm_item.required_dependencies = ["@scope/security@^2.0.0"]
        go_item = candidate(source, "danger()", "safe()", 1, 1)
        go_item.language = "go"
        go_item.required_dependencies = ["example.invalid/security@v1.2.3"]
        pipfile_item = candidate(source, "danger()", "safe()", 1, 2)
        pipfile_item.language = "python"
        pipfile_item.required_dependencies = ["safe-http>=3"]
        inventory = build_dependency_inventory(
            {
                "package.json": ('{"dependencies":{"@scope/security":"^2.0.0"}}'),
                "go.mod": (
                    "module example.invalid/app\n\n"
                    "require example.invalid/security v1.2.3\n"
                ),
                "Pipfile": '[packages]\nsafe-http = ">=3"\n',
            }
        )
        self.assertEqual(
            validate_candidate_dependencies(npm_item, inventory).status,
            "passed",
        )
        self.assertEqual(
            validate_candidate_dependencies(go_item, inventory).status,
            "passed",
        )
        self.assertEqual(
            validate_candidate_dependencies(pipfile_item, inventory).status,
            "passed",
        )

    def test_enterprise_language_manifests_are_inventory_evidence(self):
        source = "danger()\n"
        requirements = [
            ("java", "org.owasp.encoder:encoder:1.3.1"),
            ("c_sharp", "Microsoft.IdentityModel.JsonWebTokens@7.6.2"),
            ("ruby", "rack-protection ~> 4.0"),
            ("php", "symfony/security-http:^7.1"),
        ]
        items = []
        for index, (language, requirement) in enumerate(requirements):
            item = candidate(source, "danger()", "safe()", 1, index)
            item.language = language
            item.required_dependencies = [requirement]
            items.append(item)
        inventory = build_dependency_inventory(
            {
                "pom.xml": (
                    "<project><dependencies><dependency>"
                    "<groupId>org.owasp.encoder</groupId>"
                    "<artifactId>encoder</artifactId><version>1.3.1</version>"
                    "</dependency></dependencies></project>"
                ),
                "src/App.csproj": (
                    '<Project><ItemGroup><PackageReference Include="Microsoft.'
                    'IdentityModel.JsonWebTokens" Version="7.6.2" />'
                    "</ItemGroup></Project>"
                ),
                "Gemfile": 'gem "rack-protection", "~> 4.0"\n',
                "composer.json": (
                    '{"require":{"php":"^8.3","symfony/security-http":"^7.1"}}'
                ),
            }
        )
        self.assertEqual(
            [validate_candidate_dependencies(item, inventory).status for item in items],
            ["passed", "passed", "passed", "passed"],
        )

    def test_manifest_backed_python_and_npm_imports_resolve_without_execution(self):
        source = "danger()\n"
        python_item = candidate(source, "danger()", "safe()", 1, 0)
        python_item.language = "python"
        python_item.required_imports = ["import secure_db"]
        npm_item = candidate(source, "danger()", "safe()", 1, 1)
        npm_item.language = "typescript"
        npm_item.required_imports = [
            'import { encode } from "@scope/security/encoding";'
        ]
        dependency_inventory = build_dependency_inventory(
            {
                "requirements.txt": "secure-db>=2\n",
                "package.json": '{"dependencies":{"@scope/security":"^2.0.0"}}',
            }
        )
        import_inventory = build_static_import_inventory(
            {"src/app.py": source}, dependency_inventory
        )
        self.assertEqual(
            validate_candidate_imports(python_item, import_inventory).status,
            "passed",
        )
        self.assertEqual(
            validate_candidate_imports(npm_item, import_inventory).status,
            "passed",
        )

    def test_javascript_local_named_export_is_checked(self):
        source = "danger()\n"
        item = candidate(source, "danger()", "safe()", 1, 0)
        item.language = "typescript"
        item.required_imports = ['import { safe } from "./security";']
        dependency_inventory = build_dependency_inventory({})
        passing = build_static_import_inventory(
            {
                "src/app.py": source,
                "src/security.ts": (
                    "export function safe() { return true; }\n"
                    "export type Safe = () => boolean;\n"
                ),
            },
            dependency_inventory,
        )
        failing = build_static_import_inventory(
            {
                "src/app.py": source,
                "src/security.ts": "export function other() { return true; }\n",
            },
            dependency_inventory,
        )
        self.assertEqual(validate_candidate_imports(item, passing).status, "passed")
        item.required_imports = ['import type { Safe } from "./security";']
        self.assertEqual(validate_candidate_imports(item, passing).status, "passed")
        failed = validate_candidate_imports(item, failing)
        self.assertEqual(failed.status, "failed")
        self.assertIn("not exported", failed.detail)

    def test_java_imports_use_local_jdk_or_manifest_namespace_evidence(self):
        source = "danger()\n"
        dependency_inventory = build_dependency_inventory(
            {
                "pom.xml": (
                    "<project><dependencies><dependency>"
                    "<groupId>org.owasp.encoder</groupId>"
                    "<artifactId>encoder</artifactId><version>1.3.1</version>"
                    "</dependency></dependencies></project>"
                )
            }
        )
        import_inventory = build_static_import_inventory(
            {
                "src/app.py": source,
                "src/main/java/com/acme/Safe.java": (
                    "package com.acme; public class Safe {}\n"
                ),
            },
            dependency_inventory,
        )
        imports = [
            "import com.acme.Safe;",
            "import java.time.Instant;",
            "import org.owasp.encoder.Encode;",
        ]
        for index, required_import in enumerate(imports):
            item = candidate(source, "danger()", "safe()", 1, index)
            item.language = "java"
            item.required_imports = [required_import]
            self.assertEqual(
                validate_candidate_imports(item, import_inventory).status,
                "passed",
            )

    def test_go_replacement_imports_resolve_to_local_and_declared_modules(self):
        source = "danger()\n"
        dependency_inventory = build_dependency_inventory(
            {
                "go.mod": (
                    "module example.invalid/app\n\n"
                    "require example.invalid/security v1.2.3\n"
                )
            }
        )
        import_inventory = build_static_import_inventory(
            {
                "go.mod": "module example.invalid/app\n",
                "main.go": "package main\n",
                "internal/safe/safe.go": "package safe\n",
            },
            dependency_inventory,
        )
        item = candidate(
            source,
            "danger()",
            (
                'package main\nimport "example.invalid/app/internal/safe"\n'
                'import security "example.invalid/security/client"\n'
                "func main() {}\n"
            ),
            1,
            0,
        )
        item.language = "go"
        check = validate_candidate_imports(item, import_inventory)
        self.assertEqual(check.status, "passed")
        self.assertIn("local Go package", check.detail)
        self.assertIn("declared Go module", check.detail)

    def test_unchanged_import_in_replaced_snippet_is_not_misclassified_as_introduced(
        self,
    ):
        source = "def safe():\n    return True\n\ndanger()\n"
        item = candidate(
            source,
            "import legacy_unknown\ndanger()",
            "import legacy_unknown\nsafe()",
            1,
            0,
        )
        item.language = "python"
        inventory = build_static_import_inventory(
            {"src/app.py": source}, build_dependency_inventory({})
        )
        check = validate_candidate_imports(item, inventory)
        self.assertEqual(check.status, "passed")
        self.assertIn("no unresolved imports or bare symbols", check.detail)

    def test_malformed_required_import_is_blocking(self):
        source = "danger()\n"
        item = candidate(source, "danger()", "safe()", 1, 0)
        item.language = "typescript"
        item.required_imports = ['run(); import { safe } from "./security";']
        inventory = build_static_import_inventory(
            {
                "src/app.py": source,
                "src/security.ts": "export const safe = true;\n",
            },
            build_dependency_inventory({}),
        )
        check = validate_candidate_imports(item, inventory)
        self.assertEqual(check.status, "failed")
        self.assertIn("malformed/unprovable", check.detail)

    def test_import_failures_and_evidence_are_bounded(self):
        source = "danger()\n"
        item = candidate(source, "danger()", "safe()", 1, 0)
        item.language = "python"
        item.required_imports = [
            f"import missing_module_{index}" for index in range(100)
        ]
        inventory = build_static_import_inventory(
            {"src/app.py": source}, build_dependency_inventory({})
        )
        check = validate_candidate_imports(item, inventory)
        self.assertEqual(check.status, "failed")
        self.assertIn("and 90 more", check.detail)
        self.assertLess(len(check.detail), 2_500)

    def test_gradle_dependency_and_version_mismatch_are_conservative(self):
        source = "danger()\n"
        item = candidate(source, "danger()", "safe()", 1, 0)
        item.language = "kotlin"
        item.required_dependencies = ["com.example:security:2.0.0"]
        inventory = build_dependency_inventory(
            {
                "build.gradle.kts": (
                    'dependencies { implementation("com.example:security:1.0.0") }'
                )
            }
        )
        check = validate_candidate_dependencies(item, inventory)
        self.assertEqual(check.status, "failed")
        self.assertIn("version compatibility unproven", check.detail)

    def test_dependency_failure_evidence_is_bounded(self):
        source = "danger()\n"
        item = candidate(source, "danger()", "safe()", 1, 0)
        item.language = "python"
        item.required_dependencies = [f"missing-package-{index}" for index in range(15)]
        check = validate_candidate_dependencies(
            item,
            build_dependency_inventory({}),
        )
        self.assertEqual(check.status, "failed")
        self.assertIn("and 5 more", check.detail)
        self.assertLess(len(check.detail), 2_500)

    def test_manual_steps_block_automatic_source_promotion(self):
        source = "danger()\n"
        item = candidate(source, "danger()", "safe()", 1, 0)
        item.manual_steps = ["Rotate the production credential"]
        plan, decisions, patched = plan_file_patch(
            file_path="src/app.py",
            source=source,
            expected_source_hash=source_hash(source),
            candidates=[item],
        )
        self.assertEqual(patched, source)
        self.assertEqual(decisions[0].status, "conflict")
        self.assertEqual(plan.validation_checks[0].stage, "manual_requirements")
        self.assertEqual(plan.validation_checks[0].status, "failed")

    def test_second_application_is_rejected_by_original_snapshot_hash(self):
        source = "danger()\n"
        item = candidate(source, "danger()", "safe()", 1, 0)
        _, _, patched = plan_file_patch(
            file_path="src/app.py",
            source=source,
            expected_source_hash=source_hash(source),
            candidates=[item],
        )
        _, decisions, second = plan_file_patch(
            file_path="src/app.py",
            source=patched,
            expected_source_hash=source_hash(source),
            candidates=[item],
        )
        self.assertEqual(second, patched)
        self.assertEqual(decisions[0].status, "snapshot_mismatch")

    def test_generated_vendor_path_is_excluded_unless_explicitly_allowed(self):
        source = "danger()\n"
        item = candidate(source, "danger()", "safe()", 1, 0)
        item.finding.file_path = "vendor/app.py"
        plan, decisions, patched = plan_file_patch(
            file_path="vendor/app.py",
            source=source,
            expected_source_hash=source_hash(source),
            candidates=[item],
        )
        self.assertEqual((patched, plan.hunks), (source, []))
        self.assertEqual(decisions[0].status, "excluded")

    def test_atomic_syntax_failure_discards_every_hunk(self):
        source = "one()\ntwo()\n"
        items = [
            candidate(source, "one()", "safe_one()", 1, 0),
            candidate(source, "two()", "safe_two()", 2, 1),
        ]
        plan, decisions, patched = plan_file_patch(
            file_path="src/app.py",
            source=source,
            expected_source_hash=source_hash(source),
            candidates=items,
            syntax_validator=lambda _code, _path: False,
        )
        self.assertEqual((patched, plan.hunks), (source, []))
        self.assertEqual({decision.status for decision in decisions}, {"syntax_failed"})
        self.assertEqual(plan.validation_checks[0].status, "failed")

    def test_missing_parser_is_manual_review_and_never_implicit_success(self):
        source = "danger()\n"
        item = candidate(source, "danger()", "safe()", 1, 0)
        plan, decisions, patched = plan_file_patch(
            file_path="src/app.py",
            source=source,
            expected_source_hash=source_hash(source),
            candidates=[item],
            syntax_validator=lambda _code, _path: PatchValidationCheck(
                stage="syntax",
                status="tool_missing",
                tool="tree-sitter",
                detail="parser missing",
            ),
        )
        self.assertEqual((patched, plan.hunks), (source, []))
        self.assertEqual(plan.status, "manual_review_required")
        self.assertEqual(plan.validation_checks[0].status, "tool_missing")
        self.assertEqual(decisions[0].status, "validation_unavailable")
        self.assertEqual(item.validation_status, "not_run")

    def test_validation_summary_reports_partial_remediation(self):
        good_source = "danger()\n"
        good = candidate(good_source, "danger()", "safe()", 1, 0)
        good_plan, good_decisions, _ = plan_file_patch(
            file_path="src/app.py",
            source=good_source,
            expected_source_hash=source_hash(good_source),
            candidates=[good],
            syntax_validator=lambda _code, _path: True,
        )
        good.is_applied = True

        blocked = candidate(good_source, "danger()", "safe()", 1, 1)
        blocked_plan, blocked_decisions, _ = plan_file_patch(
            file_path="src/app.py",
            source=good_source,
            expected_source_hash=source_hash(good_source),
            candidates=[blocked],
            syntax_validator=lambda _code, _path: PatchValidationCheck(
                stage="syntax",
                status="tool_missing",
                tool="tree-sitter",
                detail="parser missing",
            ),
        )
        summary = build_validation_summary(
            scan_type="REMEDIATE",
            all_candidates=[good, blocked],
            file_plans=[good_plan, blocked_plan],
            decisions=[*good_decisions, *blocked_decisions],
        )
        self.assertEqual(summary["outcome"], "partial_remediation")
        self.assertEqual(summary["candidates"]["applied"], 1)
        self.assertEqual(summary["candidates"]["unverified"], 1)
        self.assertEqual(summary["candidates"]["validated"], 1)

    def test_validation_summary_reconciles_governance_and_planner_outcomes(self):
        source = "danger()\n"
        items = [
            candidate(source, "danger()", "safe()", 1, index) for index in range(5)
        ]
        validated, duplicate, conflicted, rejected, unverified = items
        validated.applicability_status = "planned"
        validated.is_applied = True
        duplicate.disposition = "duplicate"
        duplicate.applicability_status = "duplicate"
        conflicted.disposition = "conflict"
        conflicted.applicability_status = "conflict"
        rejected.disposition = "rejected"
        rejected.applicability_status = "missing"
        unverified.disposition = "conflict"
        unverified.validation_status = "not_run"
        unverified.applicability_status = "validation_unavailable"

        summary = build_validation_summary(
            scan_type="REMEDIATE",
            all_candidates=items,
            file_plans=[],
            decisions=[],
        )
        counts = summary["candidates"]
        self.assertEqual(summary["outcome"], "partial_remediation")
        self.assertEqual(counts["applied"], 1)
        self.assertEqual(counts["planned"], 1)
        self.assertEqual(counts["validated"], 1)
        self.assertEqual(counts["deduplicated"], 1)
        self.assertEqual(counts["conflicted"], 1)
        self.assertEqual(counts["rejected"], 1)
        self.assertEqual(counts["unverified"], 1)
        self.assertEqual(
            counts["proposed"],
            sum(
                counts[key]
                for key in (
                    "validated",
                    "deduplicated",
                    "conflicted",
                    "rejected",
                    "unverified",
                )
            ),
        )

    def test_noop_candidate_never_becomes_a_hunk(self):
        source = "danger()\n"
        item = candidate(source, "danger()", "danger()", 1, 0)
        plan, decisions, patched = plan_file_patch(
            file_path="src/app.py",
            source=source,
            expected_source_hash=source_hash(source),
            candidates=[item],
        )
        self.assertEqual((patched, plan.hunks), (source, []))
        self.assertEqual(decisions[0].status, "noop")


if __name__ == "__main__":
    unittest.main()
