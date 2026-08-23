import unittest

from app.infrastructure.auth.scim.schema import ScimGroupMember


class ScimReferenceSchemaTests(unittest.TestCase):
    def test_accepts_spec_ref_without_emitting_reserved_schema_key(self) -> None:
        member = ScimGroupMember.model_validate(
            {"value": "42", "$ref": "/scim/v2/Users/42"}
        )

        self.assertEqual(member.ref, "/scim/v2/Users/42")
        properties = ScimGroupMember.model_json_schema()["properties"]
        self.assertIn("ref", properties)
        self.assertNotIn("$ref", properties)


if __name__ == "__main__":
    unittest.main()
