"""断言渲染器注册表。

并行单元各自实现一个模块，模块暴露 render(params, context) -> str。
W0 只定义注册表与查找规则，不实现任何断言。
"""

RENDERER_MODULES = (
    "erc4626",
    "lending",
    "amm",
    "cross",
    "vuln",
)


def load_renderers():
    """返回 {template_name: renderer_callable}。

    每个模块暴露 RENDERERS: dict[str, callable]。
    缺失模块或缺失模板由调用方标记 adapter_required。
    """
    import importlib

    registry = {}
    for name in RENDERER_MODULES:
        try:
            module = importlib.import_module(f"{__name__}.{name}")
        except ModuleNotFoundError:
            continue
        registry.update(getattr(module, "RENDERERS", {}))
    return registry
