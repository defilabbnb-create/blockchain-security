"""Evidence-backed protocol invariant templates."""

TEMPLATES = {
    'erc4626': (
        {
            'template': 'share_price_monotonic',
            'name': '份额价格单调性',
            'description': '在排除捐赠和费用等外部资产变化后，正常存取款操作不应造成剩余份额价格无解释下降。',
            'params': {'assetsField': 'totalAssets', 'sharesField': 'totalSupply', 'decimals': '$decimals'},
        },
        {
            'template': 'withdraw_preserves_remaining_value',
            'name': '赎回保留剩余价值',
            'description': '赎回指定份额后，剩余份额对应的资产价值应与扣除赎回资产后的账本一致。',
            'params': {'assetsField': 'totalAssets', 'sharesField': 'totalSupply', 'decimals': '$decimals'},
        },
        {
            'template': 'donation_does_not_change_ledger',
            'name': '直接捐赠不改写份额账本',
            'description': '直接转入底层资产不会静默改变份额余额或供应量账本。',
            'params': {'assetsField': 'totalAssets', 'sharesField': 'totalSupply', 'decimals': '$decimals'},
        },
    ),
    'lending_pool': (
        {
            'template': 'health_factor_monotonic_on_borrow',
            'name': '借款后健康因子约束',
            'description': '借款增加风险敞口时，账户健康因子应按抵押品和债务变化重新计算并满足清算阈值。',
            'params': {'debtField': 'totalBorrows', 'supplyField': 'totalSupply', 'riskField': '$riskField', 'decimals': '$decimals'},
        },
        {
            'template': 'liquidation_does_not_create_bad_debt',
            'name': '清算不产生无担保坏账',
            'description': '清算结算后，已偿债务与抵押品扣减应守恒，未覆盖债务需显式记录。',
            'params': {'debtField': 'totalBorrows', 'riskField': '$riskField', 'decimals': '$decimals'},
        },
        {
            'template': 'interest_accrual_conserves_value',
            'name': '利息累计价值守恒',
            'description': '利息累计对借款人债务和供应方权益的变更应使用一致的累计指数与精度。',
            'params': {'debtField': 'totalBorrows', 'supplyField': 'totalSupply', 'decimals': '$decimals'},
        },
    ),
}
