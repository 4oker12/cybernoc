"""Model-transport tests using mocked Ollama responses; no paid API / GPU required."""
import unittest
from unittest.mock import patch
from cybernova_agent import model

class ProtocolTests(unittest.TestCase):
    def test_native_ollama_tool_call(self):
        payload={'message':{'content':'', 'tool_calls':[{'function':{'name':'check_file','arguments':{'path':'calculator.py'}}}]}}
        out=model._decision_from_response(payload)
        self.assertEqual(out['action'],'check_file')
        self.assertEqual(out['args']['path'],'calculator.py')

    def test_arguments_encoded_as_json_string(self):
        payload={'message':{'tool_calls':[{'function':{'name':'read_file','arguments':'{"path":"README.md"}'}}]}}
        self.assertEqual(model._decision_from_response(payload)['args']['path'],'README.md')

    def test_wrapped_tool_calls_as_text(self):
        payload={'message':{'content':'```json\n{"tool_calls":[{"function":{"name":"list_files","arguments":{}}}]}\n```'}}
        self.assertEqual(model._decision_from_response(payload)['action'],'list_files')

    def test_plain_envelope(self):
        payload={'message':{'content':'{"action":"finish","args":{"summary":"Syntax checked"},"confidence":0.9}'}}
        self.assertEqual(model._decision_from_response(payload)['args']['summary'],'Syntax checked')

    def test_multiple_tool_calls_rejected(self):
        payload={'message':{'tool_calls':[{'function':{'name':'plan','arguments':{}}},{'function':{'name':'finish','arguments':{}}}]}}
        with self.assertRaisesRegex(ValueError, 'multiple tools'):
            model._decision_from_response(payload)

    def test_unapproved_action_rejected(self):
        payload={'message':{'content':'{"action":"run_shell","args":{"command":"ls"}}'}}
        with self.assertRaises(ValueError):
            model._decision_from_response(payload)

    def test_first_native_call_success(self):
        calls=[]
        def fake(payload,timeout):
            calls.append(payload)
            return {'message':{'tool_calls':[{'function':{'name':'plan','arguments':{'steps':['Write'], 'acceptance':['Syntax valid']}}}]}}
        with patch.object(model,'_ollama',side_effect=fake):
            result=model.chat('Create a file', [], timeout=5)
        self.assertEqual(len(calls),1)
        self.assertTrue(calls[0]['tools'])
        self.assertEqual(result['action'],'plan')

    def test_auto_repair_with_schema_after_invalid_envelope(self):
        calls=[]
        def fake(payload,timeout):
            calls.append(payload)
            if len(calls)==1:
                return {'message':{'content':'{"thoughts":"test"}'}}
            return {'message':{'content':'{"action":"check_file","args":{"path":"a.py"},"reason":"validate","confidence":0.8}'}}
        with patch.object(model,'_ollama',side_effect=fake):
            result=model.chat('Validate file', [{'step':1}],timeout=5,pending_checks={'a.py'})
        self.assertEqual(result['action'],'check_file')
        self.assertEqual(len(calls),2)
        self.assertIn('format', calls[1])
        self.assertEqual(calls[0]['messages'][-1]['role'],'user')
        self.assertIn('pending_file_checks',calls[0]['messages'][-1]['content'])

    def test_two_invalid_responses_error(self):
        with patch.object(model,'_ollama',return_value={'message':{'content':'Not a JSON response'}}):
            with self.assertRaisesRegex(ValueError,'after native-tool and schema attempts'):
                model.chat('test task',[],timeout=5)

    def test_verified_files_and_pending_files_appear_in_prompt(self):
        calls=[]
        def fake(payload,timeout):
            calls.append(payload)
            return {'message':{'tool_calls':[{'function':{'name':'check_file','arguments':{'path':'README.md'}}}]}}
        with patch.object(model,'_ollama',side_effect=fake):
            model.chat('Check docs', [{'action':'list_files','result':{'ok':True}}],
                       pending_checks={'README.md'},verified_files={'converter.py'},remaining_steps=4,timeout=4)
        content=calls[0]['messages'][-1]['content']
        self.assertIn('README.md',content)
        self.assertIn('converter.py',content)
        self.assertIn('remaining_steps',content)
        self.assertIn('Do not call list_files again',content)

if __name__=='__main__':
    unittest.main()
