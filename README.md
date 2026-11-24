接了两个吊销源之后，一张已经撤销的证书在合并判断里被当成了有效：合并取第一条响应，顺序决定结果；未知状态被当作有效，缺少吊销信息反而放行；状态优先级把有效排在未知之前；新鲜度只看本次更新时间，不看下次更新时间；过期响应被当成有效而不是丢弃；签名者授权只校验名称相等，不校验签发者与授权列表；缓存键不含签发者，跨签发者串用结果；合并结果不保留逐源依据，无法追溯；策略校验不检查是否允许未知当有效；批量合并复用缓存，第二个批次命中第一个批次的结果。revoke/merge.py 是核心，tests/test_merge.py 15个红。要修的是：按上面的顺序把 10 个缺陷逐个修掉。

运行方式

在仓库根目录执行：

    python -m pytest tests -q

当前 8 个桩全部抛出 NotImplementedError，因此自检结果应恰好为 15 failed，且失败原因只能是 NotImplementedError；不应出现 collection error、fixture error、导入失败或其它异常。完成修复后目标为 15 passed。

字段表

| 字段 | 值 |
| --- | --- |
| 安全 | 多源证书吊销状态合并，撤销优先，未知与过期不得放行 |
| 漏洞检测与攻防 | 状态优先级、时间新鲜度、签名者授权、缓存键隔离、批量隔离 |
| Bugfix | 按题面顺序修复 10 个规格级缺陷，保持 API 与测试不变 |
| Python 3, pytest | 仅用 Python 标准库与 pytest，src 布局由 pyproject 注入导入路径 |
| 无外部依赖 | 不安装第三方运行依赖，不联网，不需要证书或 OCSP 服务 |

仓库布局

    sec-ocsp-merge
      README.md
      pyproject.toml
      src/revoke/__init__.py
      src/revoke/merge.py
      tests/test_merge.py

pyproject 布局说明

pyproject.toml 只承担 pytest 配置职责，其中 [tool.pytest.ini_options] 设置 pythonpath = ["src"]。因此测试从仓库根运行时可以直接 import revoke.merge，不需要先执行 pip install，也不需要 editable install。不要改成把 src 加入 sys.path 的测试代码，导入路径只由 pyproject 负责。

API 与字段约定

状态只使用三个小写值：revoked、unknown、good。status_rank 必须满足 revoked 高于 unknown，unknown 高于 good。

一条响应是字典，至少包含 source、cert_id、issuer、status、this_update、next_update、signer。source 是测试用来源标签，cert_id 是证书标识，issuer 是签发者标识，this_update 与 next_update 是带时区的 datetime，signer 是响应签名者标识。

策略是字典，包含 max_age（秒）、allow_unknown_as_good、require_signer_authorization、delegates。delegates 把签发者标识映射到显式授权签名者列表。

merge_sources 返回字典，至少包含 status 与 reasons。reasons 为每条输入响应保留一条记录，字段为 source、cert_id、issuer、status、accepted、reason；被新鲜度淘汰的记录 reason 为 expired，被签名者授权淘汰的记录 reason 为 unauthorized，其余记录给出非空的可追溯原因。批量合并返回 {"batches": [...]}，每一项与对相应批次单独调用 merge_sources 的结果完全一致，批次之间不得共享缓存或状态。

validate_policy 返回问题代码列表，安全策略返回空列表。三个问题代码分别是 max_age、allow_unknown_as_good、require_signer_authorization，分别对应无新鲜度上限、允许未知当有效、未校验签名者授权。

测试约束

tests/test_merge.py 恰好 15 个测试，是验收规格，不可修改。10 个测试分别对应 10 个缺陷，另外 5 个覆盖双向合并、顺序无关、过期剔除和批次独立。src/revoke/merge.py 是唯一实现文件，恰好 8 个桩；可以补全函数体，但不要增加或删除公开桩，不要改函数签名，也不要靠修改测试来变绿。

评分关注

先修状态语义，再修时间语义，再修授权语义，最后修缓存与批量隔离。必须保证合并结论与响应顺序无关，过期响应不参与裁决，未知状态绝不折算为有效，并且每个来源都有可核对的保留或淘汰依据。

## 字段表

| 字段 | 取值 |
| --- | --- |
| 所属领域 | 安全 |
| 子方向 | 漏洞检测与攻防 |
| 任务类型 | Bugfix |
| 语言/框架 | Python 3, pytest |
| 环境可复现等级 | 无外部依赖 |

