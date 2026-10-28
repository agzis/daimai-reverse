# 大麦 Android 9.0.35 静态逆向记录

## 公开仓库发布范围

公开版本包含自主编写的分析脚本、协议编码工具、`damai_runtime`、测试、原生加载诊断探针，以及经过审查的下载溯源、API 索引、字段来源和静态验证摘要。

**仅保留在本地，不随 Git 发布**：官方 APK、恢复的 DEX、第三方反编译源码和资源、下载的 JADX/Frida 工具、虚拟环境、编译产物、截图、抓包、设备诊断及账号相关运行记录。具体规则见 [.gitignore](.gitignore)。第三方软件需自行从合法来源获取，本仓库不重新分发。

后续章节保留原始本地研究记录；其中指向上述未发布产物的链接是本地分析路径，在 GitHub 上不可用。`analysis/verification.json` 仅记录最初的静态分析阶段，不代表后续运行阶段未启动 App。

**当前能力边界**：已还原部分 Java 层协议构造并实现官方 App 进程内 SDK 查询入口；尚未验证成功的登录态订单查询、独立安全签名生成或真实自动下单。不能将本仓库视为已可用的自动购票客户端。

公开代码的离线回归检查：

```sh
python -m unittest -v test_native_mtop_protocol
python -m unittest discover -s tests -v
```

运行依赖和 SDK 接入见第 11 节；APK 静态分析依赖及复现见第 6 节。`probe_ticket_query.py` 默认仅输出未签名请求描述，不发起网络请求。

## 结论与范围

已下载 APK、恢复内嵌业务 DEX，定位演出详情/SKU 查询与 Ultron 下单链，并追踪请求签名、设备环境检查、验证码和限流处理。

- **查询可售状态**：详情请求与 SKU 子页请求分离；SKU 返回场次、票档、可售/可点击/按钮状态等信息。未证实存在一个可直接返回真实剩余票数的独立公共接口。
- **购票不是一次 create 请求**：SKU 选择进入订单页，build 构建订单组件，adjust 按需更新，校验通过才 create。create 参数来自订单组件上下文，不是简单重发 itemId、skuId。
- **请求安全不只是 Cookie 或一个 MD5**：原生 MTop 组装账号/设备/时间/业务数据，调用 SecurityGuard 签名与安全 token，再转换为 HTTP 头及表单数据。Java 层没有还原 native 签名算法。
- **反作弊分层**：加固加载、环境检测及行为特征、安全签名/设备身份、服务端挑战/流控响应。能证实客户端调用与处理逻辑，不能据此推出服务端评分规则、阈值或封禁策略。

最初的静态分析阶段未启动 App、未使用登录账号、未请求票务后端、未创建真实订单；不包含风控绕过或已验证可用的抢票客户端。后续只读联网探测见第 8 节。以下源码行为描述指 APK 中可见的正常实现路径；Surgeon 热修复分支、云配置和服务端响应可能改变实际行为。

## 1. 本地交付与溯源

|文件/目录|内容|
|---|---|
|[damai-9.0.35.apk](damai-9.0.35.apk)|原始 APK，110,956,621 字节|
|[analysis/download-source.json](analysis/download-source.json)|商店链接、下载地址、版本、摘要、工具记录|
|[analysis/inventory/metadata.json](analysis/inventory/metadata.json)|包名、SDK、权限、证书、签名方案存在性|
|[analysis/inventory/AndroidManifest.xml](analysis/inventory/AndroidManifest.xml)|解码 Manifest|
|[analysis/inventory/payload-recovery.json](analysis/inventory/payload-recovery.json)|内嵌 ZIP 段偏移、CRC32、DEX SHA-256|
|[analysis/payload/](analysis/payload/)|从 assets/data.png 恢复的 25 个业务 DEX|
|[analysis/business/sources/](analysis/business/sources/)|业务 DEX 的 JADX 输出，含部分反编译失败/回退指令|
|[analysis/jadx/](analysis/jadx/)|外层 APK 的源码与资源输出|
|[analysis/api-map.json](analysis/api-map.json)|重点 API 的机器可读索引|
|[analysis/request-bytecode-evidence.json](analysis/request-bytecode-evidence.json)|8 个关键类、13 个方法的原始 DEX 字符串/调用指令摘录|
|[analysis/verification.json](analysis/verification.json)、[analysis/dex-integrity.json](analysis/dex-integrity.json)|已执行校验及限制|
|[inspect_apk.py](inspect_apk.py)|离线清单与业务 DEX 恢复脚本|
|[tools/jadx/](tools/jadx/)|JADX 1.5.6 本地工具|

来源：[应用宝大麦页面](https://a.app.qq.com/o/simple.jsp?pkgname=cn.damai)，从其公布的腾讯分发 CDN 直链改用 HTTPS 下载；不是从不明“破解版”站点获取。

- 包名：`cn.damai`；versionName：`9.0.35`；versionCode：`109003500`。
- minSdk：23；targetSdk：35；本样本 native ABI：`armeabi-v7a`。
- SHA-256：`d4b0dcec8e3834ef38182bc8134b2d77861fb39d2c12e69e3b9d37604ef7eea2`。
- MD5：`2db7e7a1342aed9014b52655c5ec9f0e`，与商店公布值一致。
- 提取证书 SHA-256：`4acd9a208af31123608cf1355ac63d53e27547387e4e254bcd232e72efe2e3c9`。
- `jarsigner -verify` 返回“jar 已验证”，同时警告自签名、不受本地信任链信任、1024-bit RSA、无时间戳。这是 JAR/v1 完整性验证，不是 APK v2 验证，也不是独立的发布者身份认证。

参考 [morluto/rea](https://github.com/morluto/rea) 的 artifact-bound evidence 方法及其 [Android 分析说明](https://github.com/morluto/rea/blob/main/docs/android-analysis.md)。实际使用独立 JADX 1.5.6 + Androguard 4.1.4；未声称安装/运行 REA MCP。REA Android 适配器要求 JDK 17+ 及专用 headless JAR，本次独立 JADX 使用本机 JDK 11。

## 2. 加固与业务代码恢复

Manifest 的 Application 为 `com.ali.mobisecenhance.ld.StubApplication`。其静态初始化加载 `cn.damai_shell_alijtca_plus`；见 [StubApplication.java:4-16](analysis/jadx/sources/com/ali/mobisecenhance/ld/StubApplication.java#L4)。外层仅有两个 DEX，不能把它们当作全部业务代码。

`assets/data.png` 实际以 ZIP local-header 开头；标准 ZIP 读取失败，因为没有可用 EOCD。按完整 local record 解压得到 25 个 DEX，共 126,199,536 字节；所有段通过 ZIP CRC32，所有 DEX 通过内部 file-size、SHA-1、Adler32 校验。恢复记录终点后还有 1,487 字节，以 central-directory magic 开始；未将这些尾部数据解释成业务代码。

**恢复不等于完整反编译成功**：外层 JADX 报 148 个错误，业务 DEX 报 134 个错误，两次均 exit 3，但已输出大量可读源码。生成 Java 中的 `UnsupportedOperationException` 可能只是 JADX 占位，不能视为原 App 的异常行为。关键 API/参数/调用另以原始 DEX 指令抽查；未覆盖所有方法或 native 指令。

## 3. 反作弊与风控

### 3.1 环境检查：有实际调用，不是只有 SDK 类名

|层|观察到的实现|证据与边界|
|---|---|---|
|native 环境检测|`RuntimeProtector` 加载 `security-wrapper`，声明 root、hook、inject、debug、emulator、mem、virtual-app 检查|[RuntimeProtector.java:8-26](analysis/business/sources/com/ali/security/RuntimeProtector.java#L8)；native 检测算法未反汇编，不能断言专门识别某个 Frida/Xposed 版本|
|初始化与缓存|`YyBeyer.init` 创建 protector；各 check 方法缓存结果；`isBGDevice` 组合 hook/inject/root|[YyBeyer.java:14-165](analysis/business/sources/com/alibaba/pictures/bricks/util/YyBeyer.java#L14)；未初始化或异常时可返回 false，false 不必然表示设备安全|
|应用接入|业务初始化调用 `YyBeyer.init`；首页延时任务调用 `YyBeyer.report`|[CommonBiz.java:1195](analysis/business/sources/cn/damai/launcher/initialize/CommonBiz.java#L1195)、[MainActivity.java:590-610](analysis/business/sources/cn/damai/homepage/MainActivity.java#L590)|
|配置门控上报|`runtime_check.enable_runtime_check == "true"` 时，收集 root/inject/hook/debug/emulator/mem，以 1/0 埋点|[YyBeyer.java:152-180](analysis/business/sources/com/alibaba/pictures/bricks/util/YyBeyer.java#L152)；不能证明当前云配置已开启|
|业务特征|推荐规则读取上述检测值；特定配置下风险命中会将行为 `bizMsg` 置为 `PICS_BLEEK`|[RecommendRule.java:650-675](analysis/business/sources/com/alibaba/pictures/behavix/rule/RecommendRule.java#L650)、[v50.java:62-75](analysis/business/sources/tb/v50.java#L62)；未见据此直接拒绝所有购票请求的证据|

### 3.2 请求身份、签名与安全 token

应用初始化链可见 `DMInitMtopImpl.init → InitUtils.a / CommonBiz.h`；`CommonBiz.h` 配置 INNER MTop 的 app-key 索引、版本、环境和 Passport 会话绑定。见 [DMInitMtopImpl.java:9-16](analysis/business/sources/cn/damai/launcher/altriax/DMInitMtopImpl.java#L9)、[CommonBiz.java:1132-1175](analysis/business/sources/cn/damai/launcher/initialize/CommonBiz.java#L1132)。

SDK 默认初始化创建 `InnerSignImpl`、filter manager，并在 handler 未配置时创建 `AntiAttackHandlerImpl`。见 [InnerMtopInitTask.java:20-100](analysis/business/sources/mtopsdk/mtop/global/init/InnerMtopInitTask.java#L20)。

- `InnerSignImpl.init` 接入 SecurityGuard、UMID、middle-tier / UnifiedSecurity / FC，并预热 AVMP。UMID 成功回调才将 token 写入 XState。见 [InnerSignImpl.java:70-145,560-610](analysis/business/sources/mtopsdk/security/InnerSignImpl.java#L70)。
- 协议 builder 收集 `utdid/uid/appKey/data/t/api/v/sid/ttid/deviceId` 等，时间取校正时间；API 与版本转小写。按分支调用 UnifiedSign 或 SecureSignature。见 [InnerProtocolParamBuilderImpl.java:94-158,224-352](analysis/business/sources/mtopsdk/mtop/protocol/builder/impl/InnerProtocolParamBuilderImpl.java#L94)。
- UnifiedSign 分支处理 `x-sign`、`x-mini-wua`、`x-umt`、可选 `x-sgext`；开启 WUA 时还处理 `wua`。空输出可能只记录日志/返回不完整参数，不能假定签名总是有效。

|HTTP 字段|源码中的来源/角色|
|---|---|
|`x-sign`|signer 返回值，经内部 `sign` 参数映射|
|`x-mini-wua`|轻量安全输出；不能凭名称推出服务端验证细节|
|`x-umt`|UMID token 对应参数|
|`x-sgext`|可选安全扩展输出|
|`x-sid` / `x-uid`|账号会话/用户标识|
|`x-utdid` / `x-devid`|设备身份相关参数|
|`x-t` / `x-appkey` / `x-ttid`|时间、应用标识、渠道/终端标识|

最终映射不是猜测：[InnerNetworkConverter.java:12-48](analysis/business/sources/mtopsdk/mtop/protocol/converter/impl/InnerNetworkConverter.java#L12) 定义上述映射；[AbstractNetworkConverter.java:104-153](analysis/business/sources/mtopsdk/mtop/protocol/converter/impl/AbstractNetworkConverter.java#L104) 将存在的值 URL encode 后放入 HTTP 头。**字段存在于映射不等于每次都非空、必发或被后端接受。**

`NEED_SESSION=false`、`NEED_ECODE=false` 只是不要求相应会话/ecode，不等于无签名、无设备风控或可匿名无限调用。build/create 另有 `useWua=true`；完整 WUA 与 mini-wua 不能混为一项。

### 3.3 验证码、登录挑战与流控

- 默认 `InnerFilterManagerImpl` 注册 `FCDuplexFilter`。旧分支调用 `AntiAttackAfterFilter` 和 flow-limit filter；新 FC 分支可交由 SecurityGuard `IFCComponent` 决策。见 [InnerFilterManagerImpl.java:5-28](analysis/business/sources/mtopsdk/framework/manager/impl/InnerFilterManagerImpl.java#L5)、[FCDuplexFilter.java:5-73](analysis/business/sources/mtopsdk/framework/filter/duplex/FCDuplexFilter.java#L5)。
- `responseCode == 419` 时，`bx-action=login` 可转登录；其他可处理情形读取 `location`，经 handler 打开包内验证码 WebView Activity。后台、无 handler/location 等情况下返回 `ANDROID_SYS_API_41X_ANTI_ATTACK`。见 [AntiAttackAfterFilter.java:8-54](analysis/business/sources/mtopsdk/framework/filter/after/AntiAttackAfterFilter.java#L8)。
- handler 防止重入，等待结果广播；成功重试 ANTI 请求池，取消/失败/超时则失败回调。存在 20 秒默认值，但实际等待可被配置覆盖。见 [AntiAttackHandlerImpl.java:5-101](analysis/business/sources/mtopsdk/mtop/antiattack/AntiAttackHandlerImpl.java#L5)。
- 验证 Activity 加载挑战 URL，按 referer 回跳广播 success；返回键为 cancel，异常为 fail。该客户端判断不证明远端验证成功。见 [CheckCodeValidateActivity.java:22-94](analysis/business/sources/mtopsdk/extra/antiattack/CheckCodeValidateActivity.java#L22)。
- `ApiLockHelper` 按 API key 保存锁定时间，期限可来自响应或配置，最终兜底 10 秒，不是固定限流窗口。见 [ApiLockHelper.java:10-65](analysis/business/sources/mtopsdk/mtop/antiattack/ApiLockHelper.java#L10)。`MtopResponse` 将 responseCode 420/相应 retCode 识别为锁定，420 + `FAIL_SYS_REQUEST_QUEUED` 识别为锁定且排队。见 [MtopResponse.java:170-185](analysis/business/sources/mtopsdk/mtop/domain/MtopResponse.java#L170)。这里保留 SDK 字段名称，不把它未经传输层核实直接称为 HTTP 状态码。

## 4. 余票/可售状态查询

### 4.1 已追踪的请求

|阶段|API / 版本|发起方式|业务参数|session / ecode|
|---|---|---|---|---|
|演出详情正常路径|`mtop.alibaba.damai.detail.getdetail` / `1.2`|Dolores 配置 get=false|`itemId`；先锋模式可能附 `dmChannel`|false / false|
|SKU 子页|`mtop.alibaba.detail.subpage.getdetail` / `2.0`|Dolores 配置 GET|`itemId`、`bizCode`、`scenario="itemsku"`、`exParams`|false / false|

证据：[ProjectItemDetailRequest.java:5-52](analysis/business/sources/cn/damai/trade/newtradeorder/ui/projectdetail/projectdetailitem/request/ProjectItemDetailRequest.java#L5)、[ProjectItemRepository.java:127-177](analysis/business/sources/cn/damai/trade/newtradeorder/ui/projectdetail/projectdetailitem/repository/ProjectItemRepository.java#L127)、[SkuDoloresRequest.java:5-42](analysis/business/sources/cn/damai/commonbusiness/seatbiz/sku/qilin/request/SkuDoloresRequest.java#L5)、[l03.java:9-18](analysis/business/sources/tb/l03.java#L9)。

注意版本陷阱：`l03` 另定义新详情 API `mtop.damai.item.detail.getdetail` 和版本常量 `1.0`，但这个 `ProjectItemDetailRequest.getVersion()` 的可见返回仍为 `1.2`。该请求仅在 debug + PRE + 开关满足时换 API 名；不能把常量池中所有新旧名称拼成一份保证有效的线上接口文档。

SKU 的 `exParams` 模型包含 `dataId/dataType/privilegeActId/activityId`。本地有保存场次时，本调用点令 `dataId=performId`、`dataType="2"`；没有缓存时设为空；非空且不为 `"0"` 的特权活动 ID 才写入。不是所有字段都在此处赋值。

### 4.2 响应读取与“余票”含义

`ProjectItemPresenter` 检查 `SpecialResultBean` 的错误与 result，将 `result` JSON 解析为 `SkuBean`；见 [ProjectItemPresenter.java:168-195](analysis/business/sources/cn/damai/trade/newtradeorder/ui/projectdetail/projectdetailitem/presenter/ProjectItemPresenter.java#L168)。

- `SkuBean`：`perform`、`performCalendar`、`itemBuyBtn`、`actionControl`。
- `PerformBean`：`performId`、`performSalable`、`buyPermission`、`skuList`。
- `PriceBean`：`skuId`、`priceId`、`clickable`、`buyPermission`、`frontEndStatus`、`status`，以及 `holdingQuantity/mq/mqw` 等数量相关字段。
- 页面实际用 `performSalable`、`clickable`、部分 `frontEndStatus` 值恢复选择；购买按钮还受 `isCanClickable`、`buyStatus` 控制。`buyStatus==1` 进入买票，2/3 进入登记/提醒，4 进入选座。

模型及消费证据：[SkuBean.java](analysis/business/sources/cn/damai/commonbusiness/seatbiz/sku/qilin/bean/SkuBean.java)、[PerformBean.java](analysis/business/sources/cn/damai/commonbusiness/seatbiz/sku/qilin/bean/PerformBean.java)、[PriceBean.java](analysis/business/sources/cn/damai/commonbusiness/seatbiz/sku/qilin/bean/PriceBean.java)、[NcovSkuFragment.java:2107-2154,2741-2767,3711-3725](analysis/business/sources/cn/damai/commonbusiness/seatbiz/sku/qilin/ui/NcovSkuFragment.java#L2107)。

**不能把 holdingQuantity/mq/mqw 直接解释成真实剩余库存数。** 本次没有后端字段定义、真实响应和销售并发证据。页面可售、按钮可点、资格检查、库存预占、创建订单、付款完成是不同状态；查询成功也不代表锁票。

## 5. 发起购票：从 SKU 到创建订单

### 5.1 UI 参数与 API 切换

`NcovSkuFragment.z.a()` 构造 `buyParam = itemId + "_" + count + "_" + skuId`，将 `rtc` 从 `SkuBean.actionControl.tradeControl.rtc` 转为 `"0"/"1"`，并附 `exParams`。大麦分支设置 `channel=damai_app`、`umpChannel=10001`；选座、拼单等分支另有扩展。`buyNow()` 检查选择后导航到 `ultron` 订单页。见 [NcovSkuFragment.java:1340-1421,1466-1488](analysis/business/sources/cn/damai/commonbusiness/seatbiz/sku/qilin/ui/NcovSkuFragment.java#L1340)。

`DMQueryKey` 读取入口 `rtc`，决定新旧订单 API；正常环境 domain 为 `mtop.damai.cn`。见 [DMQueryKey.java:24-73](analysis/business/sources/cn/damai/ultron/net/DMQueryKey.java#L24)。不是“新版 APK 所有订单一定使用新 API”。

|操作|新 API / 版本|旧 API / 版本|请求配置|
|---|---|---|---|
|build|`mtop.damai.trade.order.build` / `1.0`|`mtop.trade.order.build` / `4.0`|POST，session=true，ecode=true，WUA=true|
|adjust|`mtop.damai.trade.order.adjust` / `1.0`|`mtop.trade.order.adjust` / `5.0`|POST，session=true，ecode=true；此构造处未设 useWua|
|create|`mtop.damai.trade.order.create` / `1.0`|`mtop.trade.order.create` / `4.0`|POST，session=true，ecode=true，WUA=true|

证据：[UltronBuildOrder.java](analysis/business/sources/cn/damai/ultron/net/api/UltronBuildOrder.java)、[UltronAdjustOrder.java](analysis/business/sources/cn/damai/ultron/net/api/UltronAdjustOrder.java)、[UltronCreateOrder.java](analysis/business/sources/cn/damai/ultron/net/api/UltronCreateOrder.java)、[UltronDataManager.java:163-223](analysis/business/sources/cn/damai/ultron/net/UltronDataManager.java#L163)。

### 5.2 build 与后续上下文

`UltronParamsMaker.makeBuildOrderParams` 直接读取 `purchase_from`，**默认 2**：

- 2：`buyNow="true"`，读取入口的 `buyParam/exParams`。
- 1：优先使用序列化 `buildOrderParams` Map；否则为购物车路径，`buyNow="false"`，读取 `cartIds/buyParam/bookingDate/entranceDate`。
- 其他值：从 Intent URI query 取参数。

`addExtraParams` 补 `websiteLanguage`。首次 build 可能追加 `exParams.initIdHashNoList`，选座路径可能修正座位参数。见 [UltronParamsMaker.java:8-103](analysis/business/sources/cn/damai/ultron/net/UltronParamsMaker.java#L8)、[UltronDataManager.java:534-618](analysis/business/sources/cn/damai/ultron/net/UltronDataManager.java#L534)。

build 响应用于 `composeComponents`，形成订单页上下文。adjust 对触发组件生成 `asyncRequestData`；create 对该上下文生成 `submitRequestData`，序列化到 `params`，配置要求时会压缩。见 [DMOrderBuildRequest.java:12-78](analysis/business/sources/cn/damai/ultron/net/DMOrderBuildRequest.java#L12)、[DMRequester.java:425-469](analysis/business/sources/com/taobao/android/ultron/datamodel/imp/DMRequester.java#L425)。因此不能把 build 输入直接当 create 的完整输入，也不应把未调用的 `makeCreateOrderParams` 工具方法当成当前提交链。

`UltronPresenter.createOrder` 经过本地验证，之后 `createOrderValidateSuccess` 才发送 create requester。成功派发 `submitSuccessEvent`；adjust 是按需步骤，不是每次都必发。见 [UltronPresenter.java:130-220](analysis/business/sources/cn/damai/ultron/net/UltronPresenter.java#L130)。

### 5.3 网关与 HTTP 形态

订单 domain 的传递已闭合：`DMQueryKey → Request.setDomain → DMOrderBuildRequest/y60 → DMRequester.g → MtopBusiness.setCustomDomain`；见 [DMOrderBuildRequest.java:18-29](analysis/business/sources/cn/damai/ultron/net/DMOrderBuildRequest.java#L18)、[DMRequester.java:387-414,470-502](analysis/business/sources/com/taobao/android/ultron/datamodel/imp/DMRequester.java#L387)。订单 create/adjust 也使用同一 requester 网络适配体系。

原生 MTop 默认 HTTPS，入口 `gw`；converter 组合 `protocol + domain + /gw/ + lowercase(api) + / + version + /`。POST 使用 `application/x-www-form-urlencoded;charset=UTF-8`，内部 `data` 是 JSON 字符串，再进行表单编码；GET 则进入 query。签名相关参数经前述映射移入 HTTP 头。见 [MtopNetworkProp.java:50](analysis/business/sources/mtopsdk/mtop/common/MtopNetworkProp.java#L50)、[EntranceEnum.java:6](analysis/business/sources/mtopsdk/mtop/domain/EntranceEnum.java#L6)、[AbstractNetworkConverter.java:78-153,232-255,295-314](analysis/business/sources/mtopsdk/mtop/protocol/converter/impl/AbstractNetworkConverter.java#L78)。

按这条正常配置推导，新名订单 build 的 URL 形态为 `https://mtop.damai.cn/gw/mtop.damai.trade.order.build/1.0/`；create/adjust 同样按各自 API/版本组合。这是**源码构建结果，不是已抓包/已请求成功的 endpoint**。详情/SKU 不能直接照搬订单 custom domain：其 Dolores 请求选路及线上配置仍需运行时确认；SDK 通用默认域名与订单自定义域名并不相同。

### 5.4 create 成功结果与支付

`hq0` 将 `submitSuccessEvent` 注册到 `wq0`。后者从事件中的 `MtopResponse.getDataJsonObject()` 反序列化 `DmUltronPayResultBean`，字段有 `bizOrderId`、`nextUrl`、`partSuccess`；随后走支付/选座确认等后续流程，部分成功另有提示。

证据：[hq0.java:20,33](analysis/business/sources/tb/hq0.java#L20)、[wq0.java:58-112](analysis/business/sources/tb/wq0.java#L58)、[DmUltronPayResultBean.java:5-10](analysis/business/sources/cn/damai/ultron/view/bean/DmUltronPayResultBean.java#L5)、[DmOrderActivity.java:820-830](analysis/business/sources/cn/damai/ultron/view/activity/DmOrderActivity.java#L820)。这补齐了 create 成功响应到订单 ID 模型的客户端解码证据，但不等于拿到真实响应样本，更不等于支付完成。

## 6. 复现与已执行检查

```sh
uv venv .venv
uv pip install --python .venv/bin/python androguard==4.1.4
.venv/bin/python inspect_apk.py damai-9.0.35.apk

tools/jadx/bin/jadx --no-imports --show-bad-code -j 4 -d analysis/jadx damai-9.0.35.apk
tools/jadx/bin/jadx --no-imports --show-bad-code --no-res -j 6 -d analysis/business analysis/payload/*.dex
```

两次 JADX 的 exit 3 与错误数属于已观察限制，不要将它们改写成成功退出。`inspect_apk.py` 面向本样本的 `assets/data.png` local-record 格式，不是通用脱壳器。

实际执行：下载并比对大小/MD5/SHA-256；JAR/v1 签名验证；25 个 ZIP 段与 DEX 内部摘要/长度验证；两层 JADX 反编译；原始 DEX 定向解码 8 个关键类、13 个方法，保存调用指令摘录。未编译反编译源码，未运行 Android App，没有把静态分析说成抓包验证。

## 7. 尚未证明的内容

- native SecurityGuard/AVMP/WUA 的完整算法、密钥和设备安全状态；现有材料不足以生成可被服务端接受的签名。
- 在线真实余票数量、库存字段的完整后端语义、可售状态与实际预占的竞争条件。
- 当前线上选路、rtc/云配置取值、热修复替换逻辑、实际返回的 challenge 内容与服务端风控阈值。
- 某账号/设备是否有购买资格、某个提交是否成功、订单是否付款及最终出票。

继续验证这些问题需要自有测试设备、合法登录会话及经授权的低频观测；购票提交具有真实副作用，不能将静态推导的 HTTP 形态当作安全的试运行命令。本目录没有账号凭据、token、验证码绕过或自动下单脚本。

## 8. 林宥嘉深圳站：原生网关只读基线探测

`probe_ticket_query.py` 根据本仓库反编译出的请求类构造详情 POST 和 SKU GET，以 `itemId=1068122930586` 为默认目标。它是**未签名诊断工具，不是可用的 App 查询客户端**：不生成 SecurityGuard 签名、不伪造设备、不登录、不轮询、不自动重试、不跟随挑战跳转、不调用 build/adjust/create。默认只打印请求，加 `--execute` 才发送一次网络请求；退出码 0 表示离线构造成功或在线 MTop SUCCESS，1 表示 HTTP/业务失败，2 表示网络错误。

```sh
# 离线查看 SKU 请求；场次可通过 --perform-id 指定
python3 probe_ticket_query.py --endpoint sku

# 单次实际探测，保留响应
python3 probe_ticket_query.py --endpoint detail --execute \
  --output analysis/live-query/linyoujia-shenzhen-detail-protocol.json
```

参数依据：`ProjectItemDetailRequest`、`SkuDoloresRequest`、`SkuItem`、`ProjectItemRepository.getSubProjectDetailCheckData`；`bizCode="ali.china.damai"` 来自 `PasskeyHelper.DM_PASSKEY_BIZ_CODE_TAG`。SKU 无缓存时使用空 `exParams`，指定场次时用 `dataId` 和 `dataType="2"`；空属性省略行为尚未通过 App 抓包核实。`x-pv=6.3` 来自 `InnerProtocolParamBuilderImpl` 和 `XStateConstants.VALUE_INNER_PV`，`x-t` 使用本机秒级时间，不包含 SDK 校时。

默认 `acs.m.taobao.com` 来自 `MtopConfig.MtopDomain`；可显式选择 `--domain mtop.damai.cn`，但本轮**只测了 SDK 默认域名，尚未核实 Dolores 当前线上路由**。没有把订单专用域名当成已证实的详情/SKU 域名。

2026-10-21 11:26（UTC+8）实际结果，原始请求与响应保存于 `analysis/live-query/`：

|证据文件|请求|HTTP|业务结果|
|---|---|---|---|
|`linyoujia-shenzhen-detail.json`|初始详情基线，未带协议版本|200|`FAIL_SYS_PROTOVER_MISSED::缺少协议版本m-pv`|
|`linyoujia-shenzhen-sku.json`|初始 SKU 基线，未带协议版本|419|`FAIL_SYS_USER_VALIDATE`；`bxpunish=1`，服务端提示检查代理/VPN|
|`linyoujia-shenzhen-detail-protocol.json`|补齐源码中的 `x-pv=6.3` 与 `x-t` 后查询详情|200|`FAIL_SYS_PROTOPARAM_MISSED::缺少协议参数`；`bxpunish=1`|

这些是实际网关响应，但均不是查询业务成功。服务端提示不证明本机一定使用了代理/VPN；本轮没有返回余票、票档可售状态或开售时间。用户提供“当天 14:00 放票”作为测试背景，未用这些失败响应验证或否定该时间。当前环境 PATH 未发现 `adb` / `emulator`；完成 App 等价请求仍需可运行官方 SDK 的自有 Android 设备及正常生成的请求身份/签名。仅有 Cookie、H5 签名或这份反编译源码不足以声称已实现原生查询。

## 9. Android 模拟器安装与原生详情实测

已安装 Homebrew `android-commandlinetools`、ARM64 `openjdk@17`，通过 Google SDK Manager 安装 `platform-tools`、`emulator`、`system-images;android-30;google_apis;arm64-v8a`，创建 `damai-api30`。SDK 根目录 `/opt/homebrew/share/android-commandlinetools`，Java Home `/opt/homebrew/opt/openjdk@17/libexec/openjdk.jdk/Contents/Home`；未修改用户 shell 启动文件或替换原有 Java 11。`emulator -accel-check` 确认 Hypervisor.Framework 可用，ADB 实际观察 `sys.boot_completed=1`、Android 11、`ro.product.cpu.abilist=arm64-v8a`。

当前终端虽然报告 x86_64，硬件实际为 Apple M1 Pro。原始 `damai-9.0.35.apk` 的 75 个 native 库全为 `armeabi-v7a`，实际安装返回 `INSTALL_FAILED_NO_MATCHING_ABIS`；未修改该样本。

随后从大麦官网“下载”二维码进入官方落地页，其 `dm-landing.b9d4a837.js` 提供 [官方 APK 下载地址](https://appdownload.alicdn.com/publish/damai_android/latest/damai_android_36166323781390.apk)。下载至 `/tmp/damai-official-android.apk`，SHA-256 为 `53b25865953a4521210100a0b830b2bc73d77df9dcfe496b181e503f3dcd3363`，同时含 arm64-v8a 与 armeabi-v7a（各 75 个 native 库），实际安装成功。包管理器报告版本 **9.0.34**，不是仓库反编译的 9.0.35，不把两者视为相同构建。

```sh
export ANDROID_HOME=/opt/homebrew/share/android-commandlinetools
export JAVA_HOME=/opt/homebrew/opt/openjdk@17/libexec/openjdk.jdk/Contents/Home

# 仅在设备未运行时启动；AVD 和 SDK 已安装，无需重复创建
"$ANDROID_HOME/emulator/emulator" -avd damai-api30 -no-audio \
  -no-snapshot -no-boot-anim -no-metrics -gpu auto -port 5554

# 另一个终端，通过原样本 ProjectDetailActivity.java:648 中的正常分享协议打开
"$ANDROID_HOME/platform-tools/adb" -s emulator-5554 shell am start \
  -a android.intent.action.VIEW \
  -d 'damai://V1/ProjectPage?id=1068122930586' -p cn.damai
```

首次初始化曾发生 ANR；诊断栈分别出现 SecurityGuard app-key 读取和 FastJson 配置解析，不能据此断言是模拟器检测或服务端拒绝。正常重启并完成初始化后，首页和原生详情均已实际渲染。未 patch App、关闭安全校验或隐藏模拟器。

**2026-10-21 13:36（Asia/Shanghai）原生页面观察**：深圳站，演出日期 `2026.10.30-10.31`，价格 `¥380–1280`；倒计时提示 `10月21日 14:00开抢`，底部为 `预约抢票 / 提前选票抢票更稳`。项目弹出的售票规则也注明当日 14:00 二次公开销售。仅关闭信息提示、滚动查看并点击价格区域；没有设置预约或日历提醒、登录、提交订单。未展开 SKU 选票面板，未获得各票档可售状态或真实库存数；未设置 14:00 自动轮询。

证据：[运行与官方来源记录](analysis/live-query/linyoujia-shenzhen-android.json)、[原生详情截图](analysis/live-query/linyoujia-shenzhen-android-detail.png)。这是 App UI 端到端访问证据，不是目标详情/SKU HTTP 原文抓包，也不表示 `probe_ticket_query.py` 已具备原生签名能力。

## 10. 协议客户端目标：字段来源与隐藏安全插件

目标修正：通过反编译解释 App 的请求构造，并评估独立 API 客户端的可实现范围；模拟器 UI 操作、未签名探测、重新打包后能启动，均不作为 API 客户端成功的验收标准。“普通环境字段一致”也不能直接推导“服务端不会触发反作弊检查”。

### 10.1 不能把所有参数当成一份设备字典

|类别|字段示例|真实来源与复现边界|
|---|---|---|
|请求定义与序列化|`api`、`v`、`data`|具体请求类及业务状态；builder 将 API/版本转小写；JSON、签名输入、HTTP 表单编码是不同阶段|
|普通业务常量|`source`、`channel_from`、`osType`、`appType`、`platform`|DMBase helper 有固定值及条件注入，不能泛化成所有 Dolores/Ultron 接口都发送同一组字段|
|应用身份元数据|业务 `version`、头部 `version`、`ttid`|versionCode 与 versionName 不同；ttid 来自资源与版本组合，需与目标构建一致|
|运行时观测|型号、OS、语言、SIM、网络模式、时间|Android API、缓存及 SDK 校正时间；不是随意填写一组“真机型号”即可成立|
|设备与会话状态|UTDID、deviceId、sid、uid|SDK XState、设备 ID 管理器及账号组件；静态源码不包含可直接使用的实际会话|
|受保护安全输出|`x-sign`、`x-mini-wua`、`x-umt`、`x-sgext`、`wua`|SecurityGuard/中间层/securitybody 输出；生成分支和必需性有条件，尚未证实能脱离官方环境生成有效结果|

源码证据与字段来源已保存为 [request-field-provenance.json](analysis/request-field-provenance.json)。本次另确认公共业务 map 中的条件性 `sign` 与 MTop 最终的 `x-sign` 不是可无条件互换的同一个字段；没有提取密钥或账号值。

HTTP 编码也不能凭惯例替代源码：`NetworkConverterUtils.createParamQueryStr` 对键和值分别使用 Java `URLEncoder`，遍历 map 的现有顺序而非主动排序；空值在该方法中可被拼为字面量 `null`。上游业务头可能先编码，最终 converter 又有自己的编码规则。见 [NetworkConverterUtils.java:8-32](analysis/business/sources/mtopsdk/mtop/protocol/converter/util/NetworkConverterUtils.java#L8)、[h9.java:35-51](analysis/business/sources/tb/h9.java#L35)。这些是离线实现证据，不是成功请求样本。

### 10.2 新恢复的安全插件层

检查文件魔数发现 `libsgmain.so`、`libsgnocaptcha.so`、`libsgxdata.so` 实际是包含 `classes.dex` 的 ZIP/APK 容器，不是 ELF。已从 9.0.35 原始 APK 提取至 [security-plugins/v9035/](analysis/security-plugins/v9035/)，三个包的内部 ZIP CRC 校验通过；JADX 本次正常 exit 0，源码在 [插件反编译目录](analysis/security-plugins/v9035/jadx/sources/)。

统一安全参数的调用已从业务 Java 延伸到插件内部动态代理，再到 router，最后到 native 声明：

`InnerSignImpl.getUnifiedSign → IUnifiedSecurityComponent 动态代理 → 插件 router → JNICLibrary.doCommandNative`

末端证据：[C0013.java:5-8](analysis/security-plugins/v9035/jadx/sources/com/alibaba/wireless/security/mainplugin/C0013.java#L5)、[JNICLibrary.java:3-5](analysis/security-plugins/v9035/jadx/sources/com/taobao/wireless/security/adapter/JNICLibrary.java#L3)。对插件原始 DEX 另行解码，确认一个直接调用者和一个 native 声明，见 [native-boundary-evidence.json](analysis/security-plugins/native-boundary-evidence.json)。这证明 Java 层已经进入 native，**不证明 native 内部算法、安全状态或服务端校验规则已被还原**。

### 10.3 两版本不能混用

按现有官方来源记录，模拟器提取包 SHA-256 与第 9 节官方 9.0.34 下载记录一致；本次为其生成独立的 [9.0.34 清单和恢复输出](analysis/device/v9034/)，未覆盖 9.0.35 的分析结果。

- 三个选定安全插件在 9.0.35 armeabi-v7a 与 9.0.34 两 ABI 的对应成员逐字节一致，见 [provenance.json](analysis/security-plugins/provenance.json)。该结论不覆盖其他 native 库或完整 App。
- 对八个指定类名作原始 DEX 定向比较，方法签名并集 26 项：15 项规范化指令摘要相同，4 项两边存在但摘要不同，7 项仅出现在一侧的选定映射。见 [request-provenance-verification.json](analysis/request-provenance-verification.json)。
- 混淆类名可能跨版本对应不同对象；“未找到所选方法签名”不等于该功能消失；指令摘要不同也不单独证明业务语义不同。此比较不能作为完整版本等价证明。

### 10.4 当前可交付结论

已补齐普通字段来源、HTTP 编码及安全插件到 JNI 的边界；尚未生成任何经服务器接受的签名、安全 token 或独立客户端订单响应。这轮没有发起新的票务后端请求、读取账号会话或提交订单。

独立客户端剩余的关键问题是 native 安全输出及其运行态依赖，不是把现有探测脚本换成 App User-Agent，也不是自动点击原 App。现阶段不能承诺仅凭构造相同的可见环境参数就能避免反作弊检查，更不能把当前结果描述为“已实现可正常查询/下单的客户端”。

## 11. 程序化 SDK 查询入口（目标尚未完成）

已增加 `damai_runtime`：由 Python CLI 调用官方 App 进程内的 MTop SDK，不依赖界面点击，不导出登录凭据，也不独立伪造签名。目前依赖 Android 11 模拟器中的官方 **9.0.34**；这不是纯电脑端签名实现，也尚未实现自动创建订单。

主要代码：

- [bridge.js](damai_runtime/bridge.js)：调用官方请求包装类、MTop SDK 和真实异步回调；错误及超时不伪装为成功。
- [transport.py](damai_runtime/transport.py)：进程连接、RPC 截止时间及资源释放。
- [client.py](damai_runtime/client.py)：订单列表、订单详情、SKU 查询；有限次数调度，任一失败即停止。
- [CLI](damai_runtime/__main__.py)：`build/status/orders/order/sku`，没有未实现的 `buy` 占位命令。
- [运行依赖](requirements-runtime.txt)：固定 `frida==16.7.19`。17.24.3 与 17.23.3 在本 Android 11 环境中实际触发调试工具 sigchain 断言，已放弃使用；没有因此修改 App 风控逻辑。

### 11.1 接入与运行

现有模拟器及官方包见第 9 节。调试服务仅用于自有研究环境，不是规避检测手段。服务文件已从 Frida 官方发行页下载并放在设备 `/data/local/tmp/frida-server-16.7.19`；下列命令不清除用户数据、不重新打包 App：

```sh
uv pip install --python .venv/bin/python -r requirements-runtime.txt
.venv/bin/python -m damai_runtime build

ADB=/opt/homebrew/share/android-commandlinetools/platform-tools/adb
"$ADB" -s emulator-5554 wait-for-device
"$ADB" -s emulator-5554 root
"$ADB" -s emulator-5554 forward tcp:23942 tcp:27042
# 在单独终端保持运行；只监听设备 loopback，不暴露公网服务
"$ADB" -s emulator-5554 shell /data/local/tmp/frida-server-16.7.19 -l 127.0.0.1:27042
```

正常启动官方大麦并手动登录、完成必要验证后，在另一个终端运行：

```sh
.venv/bin/python -m damai_runtime status
.venv/bin/python -m damai_runtime orders --page 1 --page-size 20
.venv/bin/python -m damai_runtime order --order-id YOUR_ORDER_ID
# 仅在官方 App 已能正常访问目标商品后使用实际 itemId
.venv/bin/python -m damai_runtime sku --item-id YOUR_ITEM_ID
# 有限自动查询；失败不会被当作下一次查询的理由
.venv/bin/python -m damai_runtime orders --count 3 --interval 30
```

`YOUR_ORDER_ID` / `YOUR_ITEM_ID` 必须替换为本人订单或实际商品标识。查询结果仅输出到当前终端，没有默认持久化订单或账号数据。会话布尔值表示 SDK 存在 session 材料，不证明会话未过期；真实请求仍由服务端验证。

客户端只接受已核实的 9.0.34 包及只读请求包装类。订单查询使用 APK 内的 `OrderListRequest` / `OrderDetailRequest`；SKU 使用 APK 内现有的 `SkuRequest`。它不是当前详情页 Dolores 调用的抓包复刻，尚不能宣称与线上页面的所有额外参数完全等价。

### 11.2 已执行验证与当前阻塞

- 实际运行 `python -m damai_runtime build` 成功，`status` 返回官方包 `cn.damai`、版本 9.0.34、`has_session=false`。
- 在真实 App 进程中构造三个官方请求包装类，全部得到合法 MTop 请求，并核实 API/版本/session/ecode；此构造探针没有调用 `startRequest`。见 [official-wrapper-construction.json](analysis/runtime/official-wrapper-construction.json)。
- `orders --count 2` 实际以退出码 4 停止，原因是未登录，未派发订单查询，不会继续两次调度。
- 此前 raw MTop 请求在修正构造器重载后实际收到 `419 / ANDROID_SYS_API_41X_ANTI_ATTACK`；不是业务成功，也不是新加入的包装类请求成功证据。原始结果见 [sdk-sku-readonly.json](analysis/runtime/sdk-sku-readonly.json)。没有通过更换环境字段自动重试这个拒绝。
- 本地五项回归测试通过，覆盖 HTTP 200 但业务拒绝时停止、未知超时不重放、缺会话不派发、版本不匹配及成功判定；**测试不证明后端查询或购票成功**。

完整范围见 [runtime/verification.json](analysis/runtime/verification.json)。当前还需要本人完成官方 App 登录/验证，并提供项目、场次、票档、数量、合法购票人及价格上限，才能继续取得真实 build 响应、实现提交上下文和验收真实创建订单。未创建订单、未付款，完整目标保持未完成。
