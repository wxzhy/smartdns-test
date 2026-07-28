class AioDNSResolver(BaseResolver):
    def __init__(self, config: AioDNSResolverConfig):
        super().__init__(config)
        self.resolver = Resolver()
