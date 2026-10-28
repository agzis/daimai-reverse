const Java = globalThis.Java;
if (Java === undefined) throw new Error('This runtime requires Frida 16.7.19 with its built-in Java bridge');

const PACKAGE = 'cn.damai';
const active = new Set();

function appContext() {
  const ActivityThread = Java.use('android.app.ActivityThread');
  const app = ActivityThread.currentApplication();
  if (app === null) throw new Error('Damai application is not running');
  return app.getApplicationContext();
}

function appInfo() {
  const context = appContext();
  const pkg = context.getPackageName().toString();
  if (pkg !== PACKAGE) throw new Error(`Unexpected app package: ${pkg}`);
  const version = context.getPackageManager().getPackageInfo(pkg, 0).versionName.value.toString();
  return { context, package: pkg, version };
}

function withApp(fn) {
  return new Promise((resolve, reject) => {
    Java.perform(() => {
      try {
        const info = appInfo();
        Java.classFactory.loader = info.context.getClassLoader();
        resolve(fn(info.context, info));
      } catch (e) {
        reject(new Error(`App runtime unavailable: ${javaError(e)}`));
      }
    });
  });
}

function javaError(e) {
  try { return e.getClass ? e.getClass().getName().toString() : 'JavaScriptError'; } catch (_) { return 'Unknown error'; }
}

function status() {
  return withApp((context, info) => {
    const Mtop = Java.use('mtopsdk.mtop.intf.Mtop');
    const Id = Java.use('mtopsdk.mtop.intf.Mtop$Id');
    const config = Java.use('cn.damai.common.AppConfig').l();
    const instance = Mtop.instance(Id.INNER.value, context, config).registerTtid(config);
    if (instance === null) throw new Error('Unable to obtain official Mtop instance');
    const sid = instance.getMultiAccountSid(null);
    return { package: info.package, version: info.version, has_session: sid !== null && sid.toString().length > 0 };
  });
}

function request(spec) {
  if (!spec || typeof spec !== 'object') throw new Error('spec must be an object');
  for (const key of ['api', 'version']) if (typeof spec[key] !== 'string' || !spec[key]) throw new Error(`${key} is required`);
  if (!spec.data || typeof spec.data !== 'object' || Array.isArray(spec.data)) throw new Error('data must be an object');
  const method = spec.method;
  if (method !== 'GET' && method !== 'POST') throw new Error('method must be GET or POST');
  const timeoutMs = Number(spec.timeout_ms);
  if (!Number.isFinite(timeoutMs) || timeoutMs <= 0) throw new Error('timeout_ms must be positive');

  return new Promise((resolve, reject) => {
    let business = null;
    let timer = null;
    let settled = false;
    const refs = { listener: null };
    const finish = (err, value) => {
      if (settled) return;
      settled = true;
      if (timer !== null) clearTimeout(timer);
      active.delete(refs);
      refs.listener = null;
      if (err) reject(err); else resolve(value);
    };
    const respond = (source, response) => {
      try {
        if (response === null) {
          finish(new Error('SDK callback has no MtopResponse; outcome unknown'));
          return;
        }
        const code = response.getRetCode();
        const raw = response.getDataJsonObject();
        const message = response.getRetMsg();
        finish(null, {
          source,
          ret: code === null ? null : code.toString(),
          data: raw === null ? null : JSON.parse(raw.toString()),
          http_status: Number(response.getResponseCode()),
          error: source === 'onSuccess' ? null : (message === null ? source : message.toString())
        });
      } catch (e) {
        finish(new Error(`Unable to decode SDK response: ${javaError(e)}`));
      }
    };
    try {
      Java.perform(() => {
        try {
          const { context } = appInfo();
          const loader = context.getClassLoader();
          Java.classFactory.loader = loader;
          if (spec.request_class) {
            const allowed = new Set([
              'cn.damai.trade.newtradeorder.ui.orderlist.net.OrderListRequest',
              'cn.damai.trade.newtradeorder.ui.orderdetail.net.OrderDetailRequest',
              'cn.damai.commonbusiness.seatbiz.sku.qilin.request.SkuRequest'
            ]);
            if (!allowed.has(spec.request_class)) throw new Error('Unsupported official request wrapper');
            const RequestType = Java.use(spec.request_class);
            const FastJSON = Java.use('com.alibaba.fastjson.JSON');
            const wrapped = Java.cast(
              FastJSON.parseObject.overload('java.lang.String', 'java.lang.Class').call(FastJSON, JSON.stringify(spec.data), RequestType.class),
              RequestType
            );
            if (wrapped.getApiName().toString() !== spec.api || wrapped.getVersion().toString() !== spec.version) {
              throw new Error('Official request API/version differs from the selected contract');
            }
            wrapped.showLoginUI(false);
            business = wrapped.build();
          } else {
            const config = Java.use('cn.damai.common.AppConfig').l();
            const MtopRequest = Java.use('mtopsdk.mtop.domain.MtopRequest');
            const request = MtopRequest.$new();
            request.setApiName(spec.api);
            request.setVersion(spec.version);
            request.setNeedSession(!!spec.need_session);
            request.setNeedEcode(!!spec.need_ecode);
            request.setData(JSON.stringify(spec.data));
            if (!request.isLegalRequest()) throw new Error('Constructed MtopRequest is invalid');
            const Mtop = Java.use('mtopsdk.mtop.intf.Mtop');
            const Id = Java.use('mtopsdk.mtop.intf.Mtop$Id');
            const instance = Mtop.instance(Id.INNER.value, context, config).registerTtid(config);
            if (instance === null) throw new Error('Unable to obtain official Mtop instance');
            const Business = Java.use('com.taobao.tao.remotebusiness.MtopBusiness');
            business = Business.build.overload('mtopsdk.mtop.intf.Mtop', 'mtopsdk.mtop.domain.MtopRequest').call(Business, instance, request);
          }
          if (business === null) throw new Error('Official SDK request build returned null');
          business.showLoginUI(false);
          if (spec.domain) business.setCustomDomain(spec.domain);
          const MethodEnum = Java.use('mtopsdk.mtop.domain.MethodEnum');
          business.reqMethod(method === 'GET' ? MethodEnum.GET.value : MethodEnum.POST.value);
          if (spec.use_wua) business.useWua();

          const Listener = Java.registerClass({
            name: `org.omp.damai.RuntimeListener${Date.now()}${Math.floor(Math.random() * 100000)}`,
            implements: [Java.use('com.taobao.tao.remotebusiness.IRemoteBaseListener')],
            methods: {
              onSuccess: [{ returnType: 'void', argumentTypes: ['int', 'mtopsdk.mtop.domain.MtopResponse', 'mtopsdk.mtop.domain.BaseOutDo', 'java.lang.Object'], implementation: function (_requestType, response, _out, _context) {
                respond('onSuccess', response);
              } }],
              onError: [{ returnType: 'void', argumentTypes: ['int', 'mtopsdk.mtop.domain.MtopResponse', 'java.lang.Object'], implementation: function (_requestType, response, _context) {
                respond('onError', response);
              } }],
              onSystemError: [{ returnType: 'void', argumentTypes: ['int', 'mtopsdk.mtop.domain.MtopResponse', 'java.lang.Object'], implementation: function (_requestType, response, _context) {
                respond('onSystemError', response);
              } }]
            }
          });
          refs.listener = Listener.$new();
          active.add(refs);
          timer = setTimeout(() => {
            try { if (business !== null) business.cancelRequest(); } catch (_) {}
            finish(new Error('SDK request timed out; result is unknown'));
          }, timeoutMs);
          business.registerListener(refs.listener);
          business.startRequest(null);
        } catch (e) { finish(new Error(`SDK request setup failed: ${javaError(e)}`)); }
      });
    } catch (e) { finish(new Error(`Frida Java bridge failed: ${javaError(e)}`)); }
  });
}

export { withApp, request, status };
