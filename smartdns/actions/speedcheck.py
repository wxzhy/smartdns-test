from dns.rdatatype import RdataType
from loguru import logger

from smartdns.actions._helper import replace_reponse_ipinfo
from smartdns.actions._ping import speedtest
from smartdns.actions.base import BaseAction
from smartdns.models.action import PingConfig, SpeedcheckConfig
from smartdns.models.context import Context, Response
from smartdns.models.geodata import IPInfo
from smartdns.routing.matcher import match_response


class SpeedcheckAction(BaseAction):
    def __init__(self, config: SpeedcheckConfig):
        super().__init__(config)
        self._speedtest = config.ping_config
        self._matcher = config.match_ip
        self._num = config.max_num
        self._threshold = config.threshold

    async def start(self) -> None:
        logger.info(f"启动 Speedcheck Action {self.name}，ping 配置: {self._speedtest}")

    async def on_resolver(self, context: Context, response: Response) -> None:
        """转发到 resolver 之后调用，收集并对IP测速。"""
        logger.debug(f"Speedcheck Action {self.name} 开始处理应答")
        if response.ip_infos is None:
            return
        if not match_response(self._matcher, response):
            logger.debug(
                f"Speedcheck Action {self.name} 跳过不匹配的应答: {response.ans}"
            )
            return
        # 跳过非A/AAAA类型的应答
        if response.ans is None or response.ans.rdtype not in (
            RdataType.A,
            RdataType.AAAA,
        ):
            logger.debug(
                f"Speedcheck Action {self.name} 跳过非A/AAAA类型的应答: {response.ans}"
            )
            return
        if context.ip_infos is None:
            context.ip_infos = {}
        for ip_info in response.ip_infos:
            if ip_info.ip not in context.ip_infos:
                context.ip_infos[ip_info.ip] = ip_info
                rtt = await speedtest(ip_info.ip, config=self._speedtest)
                ip_info.rtt = rtt
                logger.debug(
                    f"Speedcheck Action {self.name} 测速结果: {ip_info.ip} -> {rtt} ms"
                )

    async def on_response(self, context: Context) -> None:
        """转发到客户端之前调用，重写IP信息。"""
        logger.debug(f"Speedcheck Action {self.name} 开始处理响应")
        if context.candidates is None or context.ip_infos is None:
            logger.debug(f"Speedcheck Action {self.name} 没有候选响应或IP信息")
            return
        if not context.ip_infos:
            logger.debug(f"Speedcheck Action {self.name} 没有可用的IP信息")
            return
        # 对结果排序
        ips = sorted(
            context.ip_infos.items(),
            key=lambda x: x[1].rtt if x[1].rtt is not None else float("inf"),
        )
        best: IPInfo = ips[0][1]
        logger.debug(
            f"Speedcheck Action {self.name} 最优IP: {best.ip}，RTT: {best.rtt} ms"
        )
        if best.rtt is None or best.rtt == float("inf"):
            logger.debug(f"Speedcheck Action {self.name} 最优IP RTT为None，跳过替换")
            return
        # 选取最优响应
        if best.resolver is not None:
            logger.debug(
                f"Speedcheck Action {self.name} 最优IP对应的解析器: {best.resolver}"
            )
            context.response = context.candidates[best.resolver]
        if context.response is None:
            logger.debug(f"Speedcheck Action {self.name} 没有可用的响应，跳过替换")
            return
        # 选取IP
        results = {}
        for ip, info in ips:
            if info.country != best.country:
                continue
            if info.rtt is None or info.rtt - best.rtt > self._threshold:
                continue
            results[ip] = info
            if len(results) >= self._num:
                break
        # 替换IP信息
        replace_reponse_ipinfo(context.response, results)
