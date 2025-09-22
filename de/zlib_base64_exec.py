import zlib
import base64
import re


def decode_layer(payload):
    """
    单层解码：反转 -> Base64解码 -> zlib解压缩
    """
    try:
        # 假设payload是bytes，如果是str则转换为bytes
        if isinstance(payload, str):
            payload = payload.encode('utf-8')

        # 反转
        reversed_payload = payload[::-1]

        # Base64解码
        b64_decoded = base64.b64decode(reversed_payload)

        # zlib解压缩
        decompressed = zlib.decompress(b64_decoded)

        return decompressed
    except Exception as e:
        print(f"解码错误: {e}")
        return None


def extract_inner_payload(decoded_str):
    """
    从解码字符串中提取内层payload，例如exec((_)(b'xxx'))
    使用正则匹配b'...'内容
    """
    pattern = r"exec\(\(_\)\(b'([^']+)'\)\)"
    match = re.search(pattern, decoded_str)
    if match:
        return match.group(1).encode('utf-8')  # 返回bytes
    return None


def multi_layer_decode(initial_payload, max_layers=200):
    """
    自动多层解密
    - initial_payload: 初始payload (str或bytes)
    - max_layers: 最大层数，防止无限循环
    """
    current = initial_payload
    layers = []
    layer_num = 1

    while layer_num <= max_layers:
        print(f"\n--- 第 {layer_num} 层解码开始 ---")

        decoded = decode_layer(current)
        if decoded is None:
            print("无法继续解码，停止。")
            break

        try:
            decoded_str = decoded.decode('utf-8')
            print(f"第 {layer_num} 层结果 (字符串): {decoded_str[:200]}...")  # 只打印前200字符，避免过长
        except UnicodeDecodeError:
            decoded_str = None
            print(f"第 {layer_num} 层结果 (二进制): {decoded[:200]}...")  # 二进制数据

        layers.append(decoded)

        # 检查是否还有内层payload
        if decoded_str and "exec((_)(b'" in decoded_str:
            inner_payload = extract_inner_payload(decoded_str)
            if inner_payload:
                current = inner_payload
                layer_num += 1
                continue

        # 如果看起来像Python代码，停止
        if decoded_str and ('import' in decoded_str or 'def ' in decoded_str or '#' in decoded_str):
            print("检测到可能为最终Python代码，停止解密。")
            break

        print("无内层payload，停止。")
        break

    return layers


# 使用示例：替换为你的完整payload
if __name__ == "__main__":
    # 这里用你提供的截断payload作为示例，实际使用时替换为完整b'==wpaxES/df/+/X1ri3UxvxzEQtboeF669i...'
    example_payload = b'==wpaxES/df/+/X1ri3UxvxzEQtboeF669iPpJ5UWFRnrOT2Xfxzi/RhqXWqsG7Gv+//YRikHB+4U5RGjHLNAL1Z8AYAeFG8yLsfEc8rnjzAHOM4rlNdWs/LYqyNTzvQuRWPDL84H1uM454sVM4o3O7kX5Qb07OSM4k4u6XrFu9/pd6DZn1FJAjx8/WDNZsUxYNevg42msmzHJnMf5H13u3QFBr55CLfWBP2Yu4ORwsn0AhihN0VfUEtdlAsRS3bV3q9HXxl7Fwb44oFCYrOTcFu4xc/SC/CUqE1IkZDroUV+jJ8/lyhqEX/PJ8uAJYvbeaIH5aYRfLTvR2eXrU5qq29cEYdX8B3cMu0z3+Q1VmiK8dWM1hfd9OE0dqGa5mjcS2H36CZGaotgZ761eqWLqtMC9CFw4C8Pk67xa6Mh3wbmU6GcQ3cs1ejhlunlMc+GLhNkfTf/777wJFkaI9YX7zEtRqWycLXlIqXXziEoXHK6R4wCAhVMgJdIypfiaPhdO16AzMkedede1rMzEUUimwH5ntynY82cb9YLIyVHoVAbtqTRmRjTE21TpJkO7pYLKKXUNUudNRcfyKWkgtmx88nUaLjkSQ2paWEvCiqfrWYptPlAxKOafYSNZ6ygCC1aYtEc5sSpP7gQedE1caid0aJcoKhQBtBp1JO9JseGmmO211BtlNKcdgdUpemaloQ38jfWi7x4s/kQ1gLOTcodLQ2/enx1ZOLrvhYDhecQfHap7NQWoEPiOJD18o7pEIaeTO6icUkG5mTSCGh75PJjdfc/IpuUj2FIikP3ASLD3jeull/kzmrF+diTqHMm1ViZunx0hUB11Ekj8lsHcLWc9rtjuYcvhpLUc0zNDyX9hUd0Q80E4Gl7/cJZBnc7i/w4l+N+dsVHZmbjr+O9RJq3t1uGdcutMxcyIBPllHtFf68SXx4tjPicGW+Yz9BaF0EeDRPVWu6M/r781viHX84PzoDPnixkvBkcnnQYw3TGpq7IBqcUGcpwytPHBP6Tr58qj6Gdq4G/l0XJOAjxhDRHliApkSpSUF6nB++wrISflc8ql4WIB4wC5Ticn+gY1UQyAv9Pesf0ZFlVkBqFkiagJL8jgBva1UdhjCItC8XJjRIkRlArE/ksrkaacrfSY2gjq/cWO4yoPnkrQhwiStYjMeUz+Ulj/RbGcFD8VnthXV+3xTVvuItVLXIhGMYAZTvwWhMdE+eTAWn3/Yrzmh3NCJnwtMdG9vwi4zGsyl2mYnC3BibLr6FnoiLWg1AAU/OkYouGiPojsEA4QDxeL0U0Q0i0Yg0PS/vkkQ2mpVXuXUskK+zn1HJVC/9rGxwaZSFHwk8Bd2zmdnrsZhwFMhfZQpTAP5q/AnhbIKA5d5Pvf4vpLPSMGbbPgU9bVSzq2SrOi3MZ1RD+lSnR70gqEl89lsfO+T+bae89pmeo4WksOkHxXnNP2JC1xTb0agN0w4SQhjG/AG/t00Msp/89E6qr0V7b3vxAw5zAAFBUpPXTvhpHkIr0/PCCBQqmlzvz+DhoHYwAfBSNQnIa6ikAMzpvpXX2qtmjw/OEUgn/4XJbQYN4x/vp0sbLszqShkZzv7ddgnjSXpccRxwmN7gnDVKRtIH/DTy6L0obRKcTRI55TcHk59CnAnT0kRtrO96xnhBrEXHyJLC6sQhhsYpjLMsL3JPVqlJtAM2eyYwgt5dnGAOtmMV6DgQ0H/MKC40CVi3ZN4P2qvhWhZxatv2VWX43swSpTpcVnV5gfcxsTJ/e5da78F45T/jUKENjP18oES3U2r3pV1wSbSoY61UMj+daewEBjeaQ395/1MeNDfTeDmpFOSnqK9VwzPfiLglSSw0Pw16aT5iG8gdmzW48Pxa1DOGX+NZTnIeeMhAutZU9kx6hFm66PuVO5l2uhPtFmij9UD+b80yAvUL3KY//sdx33bkcBtAAO3mO3Pq4YbR3c09cITss+gQyeIH0UW1JO7w91S/L0GRHBzmJrQqtHa97PPqQeRKJFp/Kyn+YJvjSjGm/lr14746BYkBfkc71nb8DFDsrzIe9o7XVvOEoqb09VzXJGCJOidIPQQgi/4dVdmqMFiW0zBVIurLyu6h3UPUWrZmhBwIjhV9PwqLdgisK//OX3OPs6Z1u8Oi4V7U+a91xN5MOTBb22D22GR0Bf4dRpxo4DrQqGAxMDFWPT4mV+UJePrfcXAlYYDclQdOeFcLoJq5l6N8fY7Zh8LQWen4x4lzXl0IGyhhIYOWIKrgMd3vVEwC7AFq65UWqm0kmS0sVtrxHvL8dzCbErfSjNzHvp5jyw9hsZVyD47atJnEvcray07DzPNmUhHu/wWjxdx5Q6UwS5ZY5zT9KJUbTgILg41axfYgvG/SX1bTyrFP5PaX/OyXTtPwWmJQCZU2+cglooQF9SglMokH0HrHtMP7t0nyEHKOaNZecmCd6D+Bcs0SD60+fFzbkDij+GHR/49+6BuGRdNXvR5Mf9evkOMKdHfU9VM0feNjXJokuFLEEcZJ+Da5b1zZAJ34Dqofs05XX+5zOFu8EVAyaxcIzaM9+lwIwP/+Q1nz4EkS6yFOIqqqrKGhPHOxaZyZ5wvvxNP1t57RlLzs4SQNZuv5IglZS+7oPgtc8dBIRzqCugkD1epj9zr0+e6BUpYK3RwWdI1pdVeXfC6guPvbt4pEWfi9MfLS9Ap7e47qGBqRfWZS/pVEF6wuxPLeu+fnS1SG6uGQHGW9h68WC4c3P6YfmxQurVSzRa4/Cd3xZV1eX21YGbeMJ5MIoryNDGxyD2jrf649VrbGvqWM3w1S6Yjt0ZYpIyxPNopbp/FUEzrxezaa/tEHhwd1IZ89LZlCbz7vh3WN8aoCeN6Lyp+t/nw6ovX2z2TvC7h1zoqdA3JiHYUi9bFzHoTqMLPEbuMGSxJ26zznA5jWaFtgc0mP+UHBjfVx8aS9W24JJEnoQKvYUJYo63RKki4hYrWqUevar37up9v2w4PVz05ZeHlc4h5Q+f29J4ywtWvfjj1Uu2pzX+l3hfQjqf5nrnFi/yb283RE5c/gsULaZYHc833KXeHQyPIpsYVrP5sgZ4UOrv+QkyaLrOpLBYs8Nx7s0YWy83aaKGeYIfcu4Rv7nGa7JwuM3Xc70PEfHpIrUcER/Qakf+A1cLY4JwFdNVqz5WpIkk7Az0Cc9jSRIOqTccEPFSCS/XbFS/KSrtaMozRbDDJKYdUj7799a9vdvj/m0wIXsfj7OfhxQY3oUW8Cmy5egzRuX8ZfzJhFJJi1hT31NZbEl3A6474cbV9ZJ/bm9X76Dx2bdTbWJgIa0Vlrch0HimTaq6vpHw84GVxDZa6ImrpgxnvmKTL/ehXwaq3otBcIrstE0tn3KKAoPXi6RKj6L9ViF2iYonowqICvkWvzBPEjv450iw9Db9JrQPvEu8jM7tCajWrxxW1vh5B6t5jhpww1g0CMMeN7ces0/xUoFaGSD78ctUXarCTJaJwEkJZUUKD5XoCEgMmd9A46hl1fUGdvEPgVP/2eqXzCenxtewfrF95rwEcA/hYCwH/ud4lhe3oHwKceW/kIoYbY05grGZyCwfeMUX97gTAXPg/uiNFEsr4P/MjXZ6IvWlolPqpLi8k8tz6otwlrFxA/uC6Cn/pmxPa0khNL5rff6AarppqPtZmcc90BF4KzJ1z+kagTxy8v25Fr2LYYQ6r16wbNoKwFlYrGjo1rnbwzCTO+VVMC+K/BxNEwUpE2ctneMNzHfL2kTcD2WBD3PJf0YO4dWyIUVz3CIxCk0qZX8eIwNwmkDE7FSKBUx0TYJgqcxsIY1wrmj2oti6W75NSJSJzuHV/bRICbh8/ydA4SO5LUiTxZu3v9q38YYbRYiUTdXTGnmzyS44C+dRkgovJlLO9j/cq1Fd2FYsufZpipad2GM7TgAW/v0QBpN/8POljA0xMOcW15OEN0GmOv+kwuG0SqUdBbkFyQAiCrglmz3k33VezN17bbo+qcIhwRejL1ZQIPLNnpWvsfl3M1Z0zJ5S1Jyker/Gz453YJCcPPknylR9lzJzhQVgwRRgi9EyXXFv91CunkDAAPHju7YLcpF7/CO5xQmvYDtrN6JwPOviOyfNWd+NyfTVleVoZz1+rhumI5tRWbdi2H5kq/PRz0/vIcI8o67bMS2WAU5xSOtN5miGJ/CvzhEGizhBMCGlRzWhS4kCx3dLPDamHOHRCtvMOfE/BwstPxFR29ckdGIzP0dKwL9vm5TYYrgbBvoJZgL2yUaDZBbllbOeZ3W5s/Jz3//KpqBRgPMWp9Ker9Uh6x+KMRcmAM/us6CEikJKj3j2mvvE1uwRDQEf+qTasNSQbSNyWARQG/K3a3El0N/A4/zZEx7crC9O+vu2XIuyPgCjN/13RszpkSMHcZ57yO8QRsKFSohDVvjVb1nR75KFK9moyjs9thHIStmqY8HnJIT7BcTFi/qr7I2wpFRI1QTzuH4tbDK9oGnkvqT9AU24Cbnxdn7qctL62IjSvmkKXxcwqeaq+LXXlfCITe/myWhLillTWhPSBpNTq7nvxUOxLjRyWdHJwXImPBYEgoF5UKJHXocBLAX8sddGo4j50HPYqi4TEIIfI6gQcG7mrn+0a/owa7V7IEF3zox0xWL8Ol9JQyjg6kA6C0r+KU0VXN/s3AiI7whGISd3HJ5NLU/lXG1sG4fQz4hcdTQwQdqUip+GVr5C6eG4twZ0il7x0RpDqC2zwuK4sXKSJTxjJ1KrMGmQJIOVDaQRp/hFoyvNfKDvfn4WBFlGfkhB66EWHANN4O9YzGhRKJ3EeZ8LvJRyph27OKPLRyCuhFnq5uL6BM6LlqjbMhx5vE1Z3b++Q+EchT05nV6mTUOaXf3G0Qbt1NKe0jeTzQgBGeI2BDunPvTwei6VocVtIrFHHBNCAMrMm8jaxHlblQa+ENmnLf7ZiYMS+3uIP38pYovFR+czb9/tkjvFjhPy+YlaJJatyl6tvgYQHTsNwBYpqZUuLH/rYH8IgP6e8u/AT5QgdGa5wUd3o2YvotZ1YWH19/vVKMtFEDGEjqxPFDjCMUy3BywYCabPuyDZsaKA8aZlHzPVD6nycmeWQyIKtE38Z+kxb7EzOHGdPvetG438wM8NU1LV5gYjTwG9kuW7B5Bq+3m+jJFPHsEPDJwGlgSQx2hLkknCW4zs3eG8+8B0gK0ceZOmK15qbj4KBIB1z2tl5LMMnyIer+cLx+O6Mro7qqrpM5e4+8IepfgDx8NIOthEguMGX8CiCG80YGRMZ4m6BBr5deyBGkfh+Gubog+/bT8xRKF6zqp+khp4OzxdVW6txzLmgAKQixLnltMKFojEiI5JGyqXTzBAKAahdabkfd2IXMxM8cus1KkrIzTfQhdTGtadtz89BAx0sjXSZLQXCL6d0wfEXZLsUbL1Wh37dcB4cQrYn4qABGdynehX6B789YqDndefBMLQvTWSOSngrWKAfqB3FTjuSnPpBdyX0do8tuJM/aWIpWxFuMhb/wuk9oEz7IhGsbkwtrpLuszaBvOLZCVIh1GVxLPOKQWWot9Te023bJvbT8pzp0140KdmDoA3my+JnBi/7Xij2hS6ZQz6AVidOb9S3OfjNbLUi/vGbToNRqvseH78iqCfr9ndYozKd2qnXRt9Hf+SeMznmpq04cw7s+dHo3JTkeOnrBqXG3u0i4pYh62tAHF6y9YV1fr1O7lxiEgZ1kEUa+iLl/uqj/mNFSWdiwmhRUBn3nrcm5/n9jcsLI/tc5w8xPDnPAVNJjTiR+5+MxsWQvgfEsKomaXo0SMZE6AAekNnwvff6+ckHYRyONImSEzHmzFclg0gI1F4S6Ret0A56QTijJ/efHYSc95jTg89zbs+mEEAusypv4+3xUvNrZsHzONoXzAVr1zvHiUWF1a/eHnlWNYF8xKG9MvGS7qobDGqvZB9dzVcRZYtSBG6uRiQ92wqht2HMY0kNsZIW4xTtcXP9E5aqcQG8obKhW++fATS0lzDns6zBzJEqoL6OZoQz4sikd19C5okHUwnIgMLEtofeo7KxXwdOpd8F3aDHs2m3ADu/qaJkkI7GKr6BxvhcGSxa3OTaCP/670h5oBvpkST986mE/FHUG3AJ2SywdusGSG6pZ/O1zvgGnJDKNSqIhhu8maYmoY3JU8Z8D7pk0iHyjmvoyWLqzZUJhBLLvTlqxj8OQlUKGRkfJWE6p+r4XWlM6oZUjIuPNSyyDq+ztvoVA+WGm0PI7mHTe6qZ3GSFVPU8kEd/bSXqGFQfayZVXDApXmzlOyQw3Q4L8iHFcE07DOLCbBIFfjZuBi7xM/UXvweBV2f2XSOCeE998ahdTUCnkyDyTq0/5GW1BstnbNerz+qwdq32hwObRmVN30eT2370uQqdmrScY1puS3zps3JTu+iAVCP6WeinlzHXuWbSJ/lne2ZW95kcKqfCk39BA+6r3xBDT7TkcDw1hrezaVOVnS+3cadypnuU98e/s+Ozz4MCy6AA1WwCTPYC8l8XZO+2v3dKhSM1FXmP9KW88uEQwnXZSsaylWdbMM0RIahbm5FhkFAjCHONPzR0OA4MQV2S1T+s7s/lMXl7+1hd+TTbBy8pb68MGOoJQWp/o/BeMRHqITEoIX1JWWqUTxO1AnIvbyfTUiL4q8iUKfMv7pNPlwsr6+R7OT5uD3s/3bKLXuVDuZBCo+hbsPKMnAPCyvpGEeiHcGoJAWl+dJ7PRagDUwDwRZ12EseymFvfaoQLo7wiJ7RQj4rfWOWWRVPqDztmqDj34NE4h1M9P+UQpqAtJeNIlRbiRzxaulWGYmSxUPdcMgnT9cPVINy/K3U8MDj71bvUjtPGU4MWzKFsSq4c3mHeWa5+G2EhVIqLvLaGT+A0K/WkVn2bpZIIId80N2WTJdKXrW3ql+UMsOBBFgh18ppB0Lcfc/u7qJ+4mD20S4Dm1+GZwPgcZuRFJyWUS5ch1AoslrSPgYciHcCNqw7b17o/ThPGy2WoPuzy79O6vdHBsPFVM+gYV+eK+kpSOq3FrXlgpgjCO2PAECoOGaSJrWrZa3SflqhXxvs5MXwwMjwDocEkxV3PmAyZfhqKgaFPxQ4c4JozkA44Q6gaACqFrpAcpqFBsIvtxMR0QW6MSCTS2+b4uo4r7fOkYkiyo0e4JmaABCZvboVs1xdNFzZcEQW8NbtvKkvFaOHQ0p5WqybnWg1uwlkf3RSEoNhVwHkRBLkGfG3l6+dH078Ai/3bpfhN6UoLFT1WpifqoxNF5K5UlWYgQl5mIl4bA2lCYT9kKkUSn3bAYAIhSmXwILAPgyX4I1Fxs6KEDsBtNzNXfnLAEUISIrcrgE7/bOEk/KZgxnzHV0HedUdY/Yrea8gImVtJVWKoKV0Edg5FxS1Q9xmN5GhbjLYUpZbMX5n0NPjpxR7lIMHn0zZ06mshH7dGTQ7h3CUBnhp/QkBYGcsUexM7t7IcvgqvzoNkpX6QI0fzlz0LG29fthON2KYJB4SHXYVOFoyo2d8xkUPNhsid4JU5rPUUmbfKkZqJQG98OhOyVLJ8qHlA5gcIepDyfV4rPDU+Dp1z7NTkyQQn64NYj57wtFsk6ZMU0DxYGPhOxOVQMIhYAHWPGHeNOgh0/QAR8OMZhoy1vcQ2AF6Epr5WQg3thN5B431jZ9oJUXpPTUQG80F7Nck5tJpU2uD+Y1ciOvSaN8tr6uA1N8uaAQNBKcumv7btnjjggGqTNUQB/4K3qAgRi6phsqg+V2087C5G0CwBsLOigN55E9fsuBdBC5UlGmg9lrKWAiSKpcn4uIcfqsJs7BYvj1jtP30WRMk6KQ5pkAMm2e2ZPa3+GqIaBxWbR0g77We7kWxa7bf3on1ZTuC/OE/i6wif5nAk6WBPmXjWHdSEu54wWJwbbC+XCzkSO2+r1RsaXC3PE0UOPnmNmAmeaCWEeJx7NSJYEeffIMjKhxGYzpJ/0ggSyoJI4YvQErtMUrTyRo6/ApqcpyOvQGOF9nRBN9bm+9CKgA8RU4/FkT/fy//33zz//VMV1GUTzzhtESchVrve7B7M4pO9u4qJ3Nsg3n+TRWoVhuWMmVwJe'

    results = multi_layer_decode(example_payload)

    # 如果需要保存最终结果
    if results:
        final = results[-1]
        try:
            with open('debug_output/decoded_final.py', 'w', encoding='utf-8') as f:
                f.write(final.decode('utf-8'))
            print("\n最终解码结果已保存到 decoded_final.py")
        except:
            print("\n最终结果为二进制，无法保存为文本。")