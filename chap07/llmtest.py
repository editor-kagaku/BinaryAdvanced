import json
from urllib.parse import urlparse
from datetime import datetime
import os
import subprocess as sp
from openai import OpenAI
import cv2
import zlib
import struct
import pprint
import codecs
import base64
from prompt_toolkit import PromptSession
from prompt_toolkit.history import InMemoryHistory
from prompt_toolkit.auto_suggest import AutoSuggestFromHistory
from rich.console import Console, ConsoleOptions, RenderResult
from rich.live import Live
from rich.markdown import CodeBlock, Markdown
from rich.syntax import Syntax
from rich import print

ptk_history = InMemoryHistory()
ptk_session = PromptSession(history=ptk_history)

# Point to the local server
# 各自のローカルLLMサーバの接続情報に更新してください
client = OpenAI(base_url="http://192.168.1.248:1234/v1", api_key="lm-studio")
# 最終回答生成用LLM
model = "gemma-3-12b-it-qat"
# 外部ツール判定用LLM
model_for_tool = "lmstudio-community/meta-llama-3.1-8b-instruct"
# 画像認識用LLM
model_for_img = "gemma-3-12b-it-qat"




def change_directory(path: str = ".") -> dict:
    try:
        os.chdir(path)
        return {
            "status": "success",
            "result": "The current directory is now "+path,
        }
    except Exception as e:
        return {"status": "error", "message": str(e)}



def decode_qrimg(path: str = "") -> dict:
    try:
        img = cv2.imread(path)
        qcd = cv2.QRCodeDetector()
        retval, decoded_info, points, straight_qrcode = qcd.detectAndDecodeMulti(img)
        if(retval):
            result = decoded_info[0]
            return {
                "status": "success",
                "decode_result": result,
            }
        else:
            return {
                "status": "failure",
                "message": "Failed to decode QR code",
            }
    except Exception as e:
        return {"status": "error", "message": str(e)}

def decode_rot13(txt: str = "") -> dict:
    try:
        result = codecs.decode(txt, "rot13")
        return {
            "status": "success",
            "decode_result": result,
        }
    except Exception as e:
        return {"status": "error", "message": str(e)}


def zip_recovery(body: str = "") -> dict:
    try:
        body = bytes.fromhex(body)
        print(body)
        result = {}
        offset_lf = 0
        while True:
            offset_lf = body.find(b"\x50\x4b\03\04",offset_lf)
            if offset_lf == -1:
                break
            header_lf = struct.unpack("<4s5H3L2H",body[offset_lf:offset_lf+30])
            (n,m) = header_lf[9:11]
            filename = body[offset_lf+30:offset_lf+30+n].decode()
            print(filename)
            if header_lf[3] == 8:
                # -15 for the window buffer will make it ignore headers/footers
                filebody = zlib.decompress(body[offset_lf+30+n+m:],-15)
                result[filename] = filebody.hex()
            offset_lf += 30 + n + m
        if any(result):
            return {
                "status": "success",
                "unzip_result": json.dumps(result),
                }
        else:
            return {"status": "error", "message": "empty"}
            
    except Exception as e:
        return {"status": "error", "message": str(e)}

def exe_cmd(cmd: str = ".") -> dict:
    try:
        proc= sp.Popen(cmd, shell=True, stdout=sp.PIPE, stderr=sp.PIPE)
        std_out, std_err = proc.communicate()
        # byte文字列で返るのでstrに
        result = std_out.decode('utf-8', errors='backslashreplace')
        result_err = std_err.decode('utf-8', errors='backslashreplace')
        return {
            "status": "success",
            "command_result": result,
            "command_stderr": result_err,
        }
    except Exception as e:
        return {"status": "error", "message": str(e)}


def img2txt(path: str = ".") -> dict:
    try:
        img = cv2.imread(path)
        # jpg画像に変換
        _, img_bin = cv2.imencode(
            '.jpg',
            img,
            (int(cv2.IMWRITE_JPEG_QUALITY), 95))
        
        base64_image = base64.b64encode(img_bin).decode("utf-8")
        tmpmsg = [{
        "role": "user",
        "content": [
            {
            "type": "text",
            "text": "Write a detailed description of the uploaded image. Only answer as instructed."},
            {
                "type": "image_url",
                "image_url": {"url": f"data:image/jpeg;base64,{base64_image}"},
            },
        ]}]
        img_content = process_stream(client.chat.completions.create(
            model=model_for_img,
            messages=tmpmsg,
            stream=True,
        ))
        return {
            "status": "success",
            "image_content": img_content,
            }
    except Exception as e:
        return {"status": "error", "message": str(e)}

tools = [
    {
        "type": "function",
        "function": {
            "name": "change_directory",
            "description": "Change the current directory, same as the cd command result",
            "parameters": {
                "type": "object",
                "properties": {
                    "path": {
                        "type": "string",
                        "description": "The directory path to change. Defaults to current directory if not specified.",
                    },
                },
                "required": [],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "decode_qrimg",
            "description": "Decodes a QR code image, the abbreviation for this command is DecQR",
            "parameters": {
                "type": "object",
                "properties": {
                    "path": {
                        "type": "string",
                        "description": "The file path to analyze. Defaults to empty if not specified.",
                    },
                },
                "required": [],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "decode_rot13",
            "description": "ROT13 Decodes a string to analyze, the abbreviation for this command is DecROT13",
            "parameters": {
                "type": "object",
                "properties": {
                    "string": {
                        "type": "string",
                        "description": "The string to analyze. Defaults to empty if not specified.",
                    },
                },
                "required": [],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "zip_recovery",
            "description": "Force zip decode the input hexadecimal string, the abbreviation for this command is unzip",
            "parameters": {
                "type": "object",
                "properties": {
                    "string": {
                        "type": "string",
                        "description": "The hexadecimal string to analyze. Defaults to empty if not specified.",
                    },
                },
                "required": [],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "img2txt",
            "description": "Convert the image file to text, the abbreviation for this command is img2txt",
            "parameters": {
                "type": "object",
                "properties": {
                    "path": {
                        "type": "string",
                        "description": "The image file path to analyze. Defaults to empty if not specified.",
                    },
                },
                "required": [],
            },
        },
    },
]

# Define the expected response structure
cmd_schema = {
    "type": "json_schema",
    "json_schema": {
        "name": "cmdline",
        "schema": {
            "type": "object",
            "properties": {
                "commands": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "properties": {
                            "thought_english": {"type": "string"},
                            "description_japanese": {"type": "string"},
                            "command": {"type": "string"},
                        },
                        "required": ["thought_english", "description_japanese", "command"]
                    },
                    "minItems": 0,
                }
            },
            "required": ["commands"]
        },
    }
}

def prettier_code_blocks():
    class SimpleCodeBlock(CodeBlock):
        def __rich_console__(
            self, console: Console, options: ConsoleOptions
        ) -> RenderResult:
            code = str(self.text).rstrip()
            yield Syntax(
                code,
                self.lexer_name,
                theme=self.theme,
                background_color='default',
                word_wrap=True,
            )
    Markdown.elements['fence'] = SimpleCodeBlock

def process_stream(stream, add_assistant_label=True):
    # Handle streaming responses from the API
    collected_text = ""
    prettier_code_blocks()
    console = Console()

    if add_assistant_label:
        header = "\nAssistant:"
    else:
        header = "\n"

    with Live('', console=console, vertical_overflow='visible') as live:
        for chunk in stream:
            delta = chunk.choices[0].delta
            # Handle regular text output
            if delta.content:
                collected_text += delta.content
                live.update(Markdown(header+collected_text))
    return collected_text



def process_tool_calls(response, messages):
    # Process multiple tool calls and return the final response and updated messages
    # Get all tool calls from the response
    tool_calls = response.choices[0].message.tool_calls

    # Create the assistant message with tool calls
    assistant_tool_call_message = {
        "role": "assistant",
        "tool_calls": [
            {
                "id": tool_call.id,
                "type": tool_call.type,
                "function": tool_call.function,
            }
            for tool_call in tool_calls
        ],
    }

    # Add the assistant's tool call message to the history
    messages.append(assistant_tool_call_message)

    # Process each tool call and collect results
    tool_results = []
    for tool_call in tool_calls:
        # For functions with no arguments, use empty dict
        arguments = (
            json.loads(tool_call.function.arguments)
            if tool_call.function.arguments.strip()
            else {}
        )

        # Determine which function to call based on the tool call name
        if tool_call.function.name == "change_directory":
            path = arguments.get("path", ".")
            result = change_directory(path)
        elif tool_call.function.name == "decode_qrimg":
            path = arguments.get("path", ".")
            result = decode_qrimg(path)
        elif tool_call.function.name == "decode_rot13":
            txt = arguments.get("string", ".")
            result = decode_rot13(txt)
        elif tool_call.function.name == "zip_recovery":
            txt = arguments.get("string", ".")
            result = zip_recovery(txt)
        elif tool_call.function.name == "img2txt":
            path = arguments.get("path", ".")
            result = img2txt(path)
        else:
            # llm tried to call a function that doesn't exist, skip
            continue

        # Add the result message
        tool_result_message = {
            "role": "tool",
            "content": json.dumps(result),
            "tool_call_id": tool_call.id,
        }
        print(tool_call.function.name)
        pprint.pprint(arguments)
        pprint.pprint(result)
        
        tool_results.append(tool_result_message)
        messages.append(tool_result_message)

    # Get the final response
    final_response = client.chat.completions.create(
        model=model,
        messages=messages,
        stream=True,
    )

    return final_response

def chat():
    messages = [
        {
            "role": "system",
            "content": "You are a helpful assistant that has useful tools. Use these capabilities whenever they might be helpful. Answer only what is asked. Speak in Japanese.",
        }
    ]

    print(
        "Assistant: Hello! I'm an assistant helping with binary file analysis. What would you like me to do?"
    )
    print("(Type 'quit' to exit)")

    while True:
        # Get user input
        user_input = ptk_session.prompt("\nYou: ", auto_suggest=AutoSuggestFromHistory()).strip()

        if user_input.lower() == "again":
            # Reverts the conversation history by one turn.
            index = -1
            for i in reversed(range(len(messages))):
                if messages[i]["role"] == "user":
                    index = i
                    break
            if index == -1:
                continue
            else:
                print("Assistant: I answer again")
                user_input = ptk_history.get_strings()[-2]
                messages = messages[:index]
        # Check for quit command
        if user_input.lower() == "quit":
            print("Assistant: Goodbye!")
            break
        elif user_input.lower() == "forget":
            # Reset the conversation history.
            messages = messages[:1]
            print("Assistant: I forget all about the conversation")
            continue
        elif user_input.lower() == "rollback":
            # Brings the conversation back to the previous turn.
            index = -1
            for i in reversed(range(len(messages))):
                if messages[i]["role"] == "user":
                    index = i
                    break
            if index == -1:
                continue
            else:
                messages = messages[:index]
                print("Assistant: Rolls back one turn of conversation")
                print("My final answer is below")
                print(messages[-1]["content"])
                continue
        elif user_input.lower() == "hint":
            # Based on the analysis results so far, advice on the next analysis work.
            messages.append({"role": "user", "content": "これまでの解析状況を踏まえて次の解析作業の助言をください"})
            response = process_stream(client.chat.completions.create(
                model=model,
                messages=messages,
                stream=True,
            ))
            messages = messages[:-1]
            continue
        elif user_input.lower() == "help":
            #Show how to use the AI ​​agent.
            tmpmsg = messages[:1]
            with open(__file__) as f:
                s = f.read()
            tmpmsg.append({
                "role": "user",
                "content": f"<情報>{s}</情報>チャットで利用者が入力するコマンドを中心に機能を説明してください"
                })
            response = process_stream(client.chat.completions.create(
                model=model,
                messages=tmpmsg,
                stream=True,
            ))
            continue
        elif user_input.lower() == "report":
            # Summary of analysis based on conversation history
            messages.append({"role": "user", "content": "これまでの会話を踏まえて解析作業経過をまとめてください"})
            response = process_stream(client.chat.completions.create(
                model=model,
                messages=messages,
                stream=True,
            ))

            # Add assistant's response to messages
            messages.append({"role": "assistant", "content": response})
            continue
        elif user_input.startswith("!!"):
            # Generates and executes the Linux commands required to answer the query, then generates a response to the query based on the results of those commands.
            messages.append({
                "role": "user",
                "content": f"次の質問の回答に必要なLinux command lineがあれば回答してください。 '{user_input[2:]}'"
            })
            response = client.chat.completions.create(
                model=model,
                messages=messages,
                response_format=cmd_schema,
                stream = True,
            )
            content = process_stream(response, False)
            messages = messages[:-1]
            # Parse and display the results
            results = json.loads(content)
            if len(results["commands"]) > 0:
                print("以下のコマンドを実行します")
                for cmd in results["commands"]:
                    print("# "+cmd["description_japanese"])
                    print(cmd["command"])

                user_input2 = input("\n問題なければ y と入力してください: ").strip()
                if user_input2.lower() == "y":
                    for i,cmd in enumerate(results["commands"]):
                        result = exe_cmd(cmd["command"])
                        if result["status"] == "success":
                            print(result["command_result"])
                        else:
                            print(result)
                        results["commands"][i]["result"]=result

                    messages.append({
                        "role": "user",
                        "content": f"<情報>{json.dumps(results)}</情報>\n{user_input[2:]}"
                    })
                    response = process_stream(client.chat.completions.create(
                        model=model,
                        messages=messages,
                        stream=True,
                    ))
                    # Add assistant's response to messages
                    messages.append({"role": "assistant", "content": response})
            continue
        elif user_input.startswith("!"):
            # Executes the Linux command following the ! and adds it to the conversation history.
            messages.append({"role": "user", "content": f"Run the Linux command line '{user_input[1:]}'"})
            result = exe_cmd(user_input[1:])
            if result["status"] == "success":
                print("\nAssistant:", result["command_result"])
            else:
                print("\nAssistant:", result)

            # Add assistant's response to messages
            messages.append(
                {
                    "role": "assistant",
                    "content": json.dumps(result),
                }
            )
            continue
        elif user_input.startswith("?"):
            # Inquiries to LLM that clearly state that no external tools are used
            messages.append({"role": "user", "content": user_input[1:]})
            response = process_stream(client.chat.completions.create(
                model=model,
                messages=messages,
                stream=True,
            ))

            # Add assistant's response to messages
            messages.append({"role": "assistant", "content": response})
            continue

        # Add user message to conversation
        messages.append({"role": "user", "content": user_input})

        try:
            # Get initial response
            response = client.chat.completions.create(
                model=model_for_tool,
                messages=messages,
                tools=tools,
            )

            # Check if the response includes tool calls
            if response.choices[0].message.tool_calls:
                # Process all tool calls and get final response
                final_response = process_tool_calls(response, messages)
                
                content = process_stream(final_response)

                # Add assistant's final response to messages
                messages.append({"role": "assistant", "content": content})
            else:
                # If no tool call, just print the response
                print("\nAssistant:", response.choices[0].message.content)

                # Add assistant's response to messages
                messages.append(
                    {
                        "role": "assistant",
                        "content": response.choices[0].message.content,
                    }
                )

        except Exception as e:
            print(f"\nAn error occurred: {str(e)}")
            exit(1)


if __name__ == "__main__":
    chat()

