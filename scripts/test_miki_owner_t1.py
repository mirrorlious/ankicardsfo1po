import unittest

import compile_miki_owner_t1 as compiler


class OwnerT1CompilerTest(unittest.TestCase):
    def test_choice_template_compiles_without_approving_raw_javascript(self):
        model = {
            "css": ".option{} .selected{} .correct{} .wrong{} .locked{}",
            "flds": [{"name": "题目"}, {"name": "正确答案"}],
        }
        template = {
            "qfmt": """
<div class="option" data-letter="A" onclick="zhCheck(this)">A</div>
<div class="option" data-letter="B" onclick="zhCheck(this)">B</div>
<script>
document.querySelectorAll('.option').forEach(function(option){
  option.addEventListener('click', function(){
    var letter = option.dataset.letter;
    option.classList.add('selected');
    if (letter === 'A') option.classList.add('correct');
    else option.classList.add('wrong');
    option.classList.add('locked');
  });
});
</script>
""",
            "afmt": "{{FrontSide}}",
        }
        report_item = {"interactionCandidate": "t1-candidate", "blockers": [], "executionApproved": False}
        plan, diagnostics = compiler.compile_plan(model, template, report_item)
        self.assertIsNotNone(plan)
        self.assertEqual(plan["profile"], "choice-judge-v1")
        self.assertEqual(plan["optionSelector"], ".option")
        self.assertEqual(plan["optionValueAttribute"], "data-letter")
        self.assertEqual(plan["answerField"], "正确答案")
        self.assertEqual(plan["correctClass"], "correct")
        self.assertEqual(plan["wrongClass"], "wrong")
        self.assertTrue(plan["planHash"].startswith("sha256:"))
        self.assertIn(".option", diagnostics["selectorHints"])
        self.assertFalse(report_item["executionApproved"])

    def test_blocked_template_never_compiles(self):
        model = {"css": ".option{} .correct{} .wrong{}", "flds": [{"name": "正确答案"}]}
        template = {"qfmt": '<div class="option" data-letter="A">A</div><script>fetch("https://example.com")</script>', "afmt": ""}
        plan, _ = compiler.compile_plan(model, template, {"interactionCandidate": "blocked", "blockers": ["network"]})
        self.assertIsNone(plan)


if __name__ == "__main__":
    unittest.main()
