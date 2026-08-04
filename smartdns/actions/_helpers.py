"""Action 共享辅助：域名排除判断与 copy-on-write 应答重建。

replace/https 动作需修改应答中的 rrset，但该 Answer/Message 可能被上游缓存或跨请求
共享；直接就地改写会污染共享对象、且需触碰 dnspython 不可变 rdata 的私有属性。
这里提供 copy-on-write：浅拷贝 Message、只替换 answer 段中的目标 rrset 并失效其索引，
原对象保持不变。
"""

from copy import copy

from dns.resolver import Answer
from dns.rrset import RRset

from smartdns.models.context import Request, Response


def is_excluded(
    request: Request, response: Response, exclude: set[str] | None
) -> bool:
    """请求域名或其 CNAME 链命中 exclude 标签集合则返回 True。"""
    if exclude is None:
        return False
    country = request.name_info.country
    if country is not None and country & exclude:
        return True
    if response.name_infos is not None:
        for cname in response.name_infos:
            if cname.country is not None and cname.country & exclude:
                return True
    return False


def replace_answer_rrset(
    response: Response, new_rrset: RRset, upstream: str
) -> Response:
    """以 copy-on-write 用 new_rrset 替换应答段中的 answer rrset，返回新 Response。

    不修改原 Answer/Message（其可能被缓存或跨请求共享）：浅拷贝 Message、用新列表替换
    answer 段中的目标 rrset，并置 index=None 令 resolve_chaining 重扫新 section。
    """
    ans = response.ans
    if ans is None or ans.rrset is None:
        return response
    old_msg = ans.response
    new_msg = copy(old_msg)
    new_msg.sections = list(old_msg.sections)
    new_msg.sections[1] = [
        new_rrset if rrset is ans.rrset else rrset for rrset in old_msg.sections[1]
    ]
    new_msg.index = None  # ty: ignore[invalid-assignment]  运行期支持 None（stub 过窄）
    new_answer = Answer(
        ans.qname,
        ans.rdtype,
        ans.rdclass,
        new_msg,
        ans.nameserver,
        ans.port,
    )
    return Response.from_answer(new_answer, upstream=upstream)
