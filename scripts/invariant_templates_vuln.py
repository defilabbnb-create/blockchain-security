"""Evidence-backed vulnerability-class invariant templates.

Every template states a property that must hold for the class to be sound, not
the defect itself.  A violated assertion means this harness observed the
property failing; it is an experiment result, never a confirmed vulnerability.

Unlike the protocol-role templates in ``invariant_templates``, these apply to any
contract exhibiting the class's semantic signature: a reentrancy candidate is
recognised from a value transfer before its state update regardless of protocol
type.  Parameters name the observation sites, and a template whose parameters
cannot be resolved is dropped rather than rendered against a guess.
"""

TEMPLATES = {
    # A balance-changing call issued before the guard it depends on is the
    # reentrancy signature.  The invariant asks for the guard to be re-checked
    # across the external call, which is what a correct implementation does.
    'reentrancy_guard_rechecked': (
        {
            'template': 'state_update_precedes_external_call',
            'name': '状态更新先于外部调用',
            'description': '在账户扣减或余额更新之后、且在外部调用返回之前完成状态更新，'
                           '重入路径无法在中间态观察到已失效的授权条件。',
            'params': {'guardField': '$guardField', 'valueField': '$valueField',
                       'toleranceBps': 0},
        },
    ),
    # Privileged state mutation reachable without an authentication check.
    # Both renderers call the privileged entry itself, so `entrypoint` has to be
    # part of the declared parameter set: the substitution was already being
    # computed, but a template that does not name a parameter never receives it.
    'access_control_guard_present': (
        {
            'template': 'privileged_entry_requires_authentication',
            'name': '特权入口需要授权',
            'description': '修改特权状态的入口在执行前应校验调用者身份，'
                           '未授权调用者不得改变该状态。',
            'params': {'guardedField': '$guardedField', 'entrypoint': '$entrypoint',
                       'toleranceBps': 0},
        },
        {
            'template': 'unauthorized_caller_cannot_mutate_state',
            'name': '未授权调用者不得改变状态',
            'description': '任意调用者直接调用特权入口不应改变被保护状态变量。',
            'params': {'guardedField': '$guardedField', 'entrypoint': '$entrypoint',
                       'toleranceBps': 0},
        },
    ),
    # Unchecked return value of a value-bearing call: the contract cannot observe
    # that the transfer failed.
    'unchecked_low_level_call': (
        {
            'template': 'call_success_is_enforced',
            'name': '低级调用成功被强制检查',
            'description': '执行资产转移的低级调用后，合约应检查其成功返回值，'
                           '失败时不得记录为已完成。',
            'params': {'ledgerField': '$ledgerField', 'toleranceBps': 0},
        },
    ),
    # Randomness or block-derived value used in a condition the caller influences.
    'bad_randomness': (
        {
            'template': 'randomness_source_is_unpredictable',
            'name': '随机来源不可被操纵',
            'description': '用于决定结果的随机或区块派生值不应是已过时区块、'
                           '可预测调用者输入或可被公开观测的确定量。',
            'params': {'valueField': '$valueField', 'toleranceBps': 0},
        },
        {
            'template': 'outcome_not_determined_by_caller_supplied_value',
            'name': '结果不由调用者输入决定',
            'description': '在同一区块同一状态下，相同调用者输入不应使判定结果'
                           '可被提前计算并利用。',
            'params': {'valueField': '$valueField', 'toleranceBps': 0},
        },
    ),
    # Arithmetic that can wrap or truncate silently.
    'arithmetic': (
        {
            'template': 'arithmetic_result_never_wraps',
            'name': '算术结果不回绕',
            'description': '涉及资产金额的加减乘结果应在数学上无溢出或截断，'
                           '否则余额或价格将被静默改写。',
            'params': {'valueField': '$valueField', 'toleranceBps': 0},
        },
        {
            'template': 'balance_delta_matches_intended_amount',
            'name': '余额变化与预期金额一致',
            'description': '一次记账操作后的余额差值应等于预期金额，'
                           '不得因溢出或截断产生偏差。',
            'params': {'ledgerField': '$ledgerField', 'toleranceBps': 0},
        },
    ),
    # Loop or unbounded work driven by attacker-controlled collection size.
    'denial_of_service': (
        {
            'template': 'unbounded_work_is_bounded',
            'name': '不可信输入的工作量有界',
            'description': '受攻击者控制的集合规模不应使单次交易工作量无界增长，'
                           '否则后续调用者会被阻断。',
            'params': {'toleranceBps': 0},
        },
        {
            'template': 'single_item_failure_does_not_block_others',
            'name': '单项失败不阻塞其他条目',
            'description': '集合中一个条目的失败不应中断整批处理并使后续条目'
                           '永久无法处理。',
            'params': {'entrypoint': '$entrypoint', 'toleranceBps': 0},
        },
    ),
}