import base64
import zlib
import marshal
import dis
import sys
import argparse
import os
import platform
from io import StringIO
import re

def decode_obfuscated_code(encoded_str, max_depth=10, depth=0, output_dir="debug_output"):
    """
    递归还原嵌套的 base64、zlib 和 marshal 混淆代码
    
    Args:
        encoded_str (bytes): 编码后的字节串（base64 编码）
        max_depth (int): 最大递归深度，防止无限递归
        depth (int): 当前递归深度
        output_dir (str): 保存调试输出的目录
    
    Returns:
        tuple: (bool, str) 是否成功及还原结果或错误信息
    """
    print(f"正在解码第 {depth + 1} 层...")
    
    if depth >= max_depth:
        return False, f"错误: 达到最大递归深度 {max_depth}，可能存在无限嵌套"

    try:
        # 创建调试输出目录
        os.makedirs(output_dir, exist_ok=True)
        
        # 步骤 1: 反转字符串
        print(f"  反转输入: {encoded_str[:20]}... (总长度: {len(encoded_str)})")
        reversed_str = encoded_str[::-1]
        
        # 步骤 2: base64 解码
        decoded_b64 = base64.b64decode(reversed_str)
        print(f"  base64 解码成功，长度: {len(decoded_b64)}")
        
        # 步骤 3: zlib 解压缩
        decompressed = zlib.decompress(decoded_b64)
        print(f"  zlib 解压缩成功，长度: {len(decompressed)}")
        
        # 步骤 4: marshal 反序列化
        code_obj = marshal.loads(decompressed)
        print(f"  marshal 反序列化成功")
        
        # 步骤 5: 尝试反汇编
        dis_output = None
        output = StringIO()
        sys.stdout = output
        try:
            dis.dis(code_obj)
            dis_output = output.getvalue()
            print(f"  反汇编输出长度: {len(dis_output)}")
        except Exception as e:
            sys.stdout = sys.__stdout__
            # 如果反汇编失败，提取代码对象的详细信息
            try:
                const_info = f"代码对象常量: {code_obj.co_consts}\n"
                const_info += f"代码对象名称: {code_obj.co_names}\n"
                const_info += f"函数名: {code_obj.co_name}\n"
                
                # 提取嵌套代码对象的常量
                nested_code_info = ""
                for const in code_obj.co_consts:
                    if isinstance(const, type(code_obj)):  # 检查是否为代码对象
                        nested_code_info += f"\n嵌套代码对象 <{const.co_name}>:\n"
                        nested_code_info += f"  常量: {const.co_consts}\n"
                        nested_code_info += f"  名称: {const.co_names}\n"
                
                debug_file = os.path.join(output_dir, f"code_info_layer_{depth + 1}.txt")
                with open(debug_file, 'w', encoding='utf-8') as f:
                    f.write(const_info + nested_code_info)
                print(f"  代码对象信息已保存至: {debug_file}")
                return False, f"深度 {depth + 1}: 反汇编失败 - {str(e)}\n{const_info}{nested_code_info}"
            except Exception as const_e:
                return False, f"深度 {depth + 1}: 反汇编失败 - {str(e)}\n无法提取代码对象信息 - {str(const_e)}"
        finally:
            sys.stdout = sys.__stdout__
        
        # 保存反汇编输出到文件
        if dis_output:
            debug_file = os.path.join(output_dir, f"dis_output_layer_{depth + 1}.txt")
            with open(debug_file, 'w', encoding='utf-8') as f:
                f.write(dis_output)
            print(f"  反汇编输出已保存至: {debug_file}")
        
        # 步骤 6: 检查是否还有嵌套的 exec 调用
        if dis_output and "exec" in dis_output:
            const_match = re.search(r"LOAD_CONST\s+\d+\s+\((b'.*?')\)", dis_output, re.DOTALL)
            if const_match:
                try:
                    nested_encoded_str = eval(const_match.group(1))  # 安全提取字节串
                    print(f"发现嵌套编码: {nested_encoded_str[:20]}...，进入第 {depth + 2} 层解码")
                    return decode_obfuscated_code(nested_encoded_str, max_depth, depth + 1, output_dir)
                except Exception as e:
                    return False, f"深度 {depth + 1}: 提取嵌套编码失败 - {str(e)}"
        
        return True, dis_output if dis_output else "深度 {depth + 1}: 无反汇编输出"
    
    except base64.binascii.Error as e:
        return False, f"深度 {depth + 1}: base64 解码失败，输入字符串格式不正确 - {str(e)}"
    except zlib.error as e:
        return False, f"深度 {depth + 1}: zlib 解压缩失败，数据可能已损坏 - {str(e)}"
    except ValueError as e:
        return False, f"深度 {depth + 1}: marshal 反序列化失败，数据可能不合法 - {str(e)}"
    except Exception as e:
        return False, f"深度 {depth + 1}: 未知异常 - {str(e)}"

def read_encoded_string(file_path):
    """
    从文件中读取 base64 编码字符串
    
    Args:
        file_path (str): 输入文件路径
    
    Returns:
        bytes: 读取的字节串，或 None 如果失败
    """
    try:
        with open(file_path, 'rb') as f:
            encoded_str = f.read().strip()
            print(f"读取文件 {file_path}，内容长度: {len(encoded_str)}")
            if encoded_str.startswith(b"b'") and encoded_str.endswith(b"'"):
                return eval(encoded_str)  # 转换为 bytes 对象
            return encoded_str  # 假设是纯 base64 编码
    except FileNotFoundError:
        print(f"错误: 文件 {file_path} 不存在")
        return None
    except Exception as e:
        print(f"读取文件失败: {str(e)}")
        return None

def main():
    """
    主函数，处理命令行参数并执行解码
    """
    print(f"当前 Python 版本: {platform.python_version()}")
    parser = argparse.ArgumentParser(description="还原嵌套的 base64、zlib 和 marshal 混淆代码")
    parser.add_argument("file", help="包含 base64 编码字符串的输入文件路径")
    args = parser.parse_args()

    encoded_str = read_encoded_string(args.file)
    if encoded_str is None:
        print(f"错误: 无法读取文件 {args.file}")
        sys.exit(1)
    
    print("开始解码...")
    success, result = decode_obfuscated_code(encoded_str)
    if success:
        print("\n最终还原的代码（反汇编形式）：")
        print(result)
    else:
        print("\n解码失败：")
        print(result)
        print("\n提示：如果反汇编失败，可能是 Python 版本不匹配。请检查 payload.txt 是否由当前 Python 版本生成。")
        print(f"当前版本: {platform.python_version()}，尝试使用 Python 3.6 或 3.7 运行。")

if __name__ == "__main__":
    main()