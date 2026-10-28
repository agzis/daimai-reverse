import com.github.unidbg.AndroidEmulator;
import com.github.unidbg.arm.backend.Unicorn2Factory;
import com.github.unidbg.linux.android.AndroidEmulatorBuilder;
import com.github.unidbg.linux.android.AndroidResolver;
import com.github.unidbg.linux.android.dvm.AbstractJni;
import com.github.unidbg.linux.android.dvm.DalvikModule;
import com.github.unidbg.linux.android.dvm.BaseVM;
import com.github.unidbg.linux.android.dvm.DvmClass;
import com.github.unidbg.linux.android.dvm.DvmObject;
import com.github.unidbg.linux.android.dvm.StringObject;
import com.github.unidbg.linux.android.dvm.VarArg;
import com.github.unidbg.linux.android.dvm.VaList;
import com.github.unidbg.linux.android.dvm.VM;
import com.github.unidbg.linux.android.dvm.array.ArrayObject;
import com.github.unidbg.linux.android.dvm.wrapper.DvmInteger;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.util.HexFormat;
import java.util.concurrent.TimeUnit;
import java.util.zip.ZipFile;
import java.util.HashSet;
import java.util.Set;
import net.dongliu.apk.parser.ApkFile;

/** Offline load/JNI-registration diagnostic; never invokes signing or backend APIs. */
public final class NativeLoadProbe {
    private static final String APK_SHA256 =
        "d4b0dcec8e3834ef38182bc8134b2d77861fb39d2c12e69e3b9d37604ef7eea2";
    private static final String LIBRARY = "lib/armeabi-v7a/libsgmainso-6.8.260704.so";

    /** Class lookup only, backed by the original plugin DEX, not invented classes. */
    private static final class PluginJni extends AbstractJni {
        private final Set<String> definitions = new HashSet<>();
        private final DvmObject<?> loader;
        private IllegalStateException sdkFailure;

        PluginJni(VM vm, Path plugin) throws Exception {
            try (ApkFile dexContainer = new ApkFile(plugin.toFile())) {
                for (var definition : dexContainer.getDexClasses()) {
                    String descriptor = definition.getClassType();
                    definitions.add(descriptor.substring(1, descriptor.length() - 1));
                }
            }
            loader = vm.resolveClass("java/lang/ClassLoader").newObject(plugin);
        }

        private DvmClass loadClass(BaseVM vm, StringObject name) {
            String internalName = name.getValue().replace('.', '/');
            if (!definitions.contains(internalName)) {
                throw new UnsupportedOperationException("Class outside original plugin DEX: " + internalName);
            }
            return vm.resolveClass(internalName);
        }

        @Override
        public DvmObject<?> newObject(
                BaseVM vm, DvmClass owner, String signature, VarArg args) {
            if (signature.equals("com/alibaba/wireless/security/open/SecException"
                    + "-><init>(Ljava/lang/String;I)V")) {
                StringObject message = args.getObjectArg(0);
                int code = args.getIntArg(1);
                String text = message == null ? null : message.getValue();
                // Preserve the native rejection, rather than replacing it with a value.
                sdkFailure = new IllegalStateException("SecurityGuard error " + code + ": " + text);
                System.err.println("NATIVE_SDK_ERROR_CODE=" + code);
                return owner.newObject(sdkFailure);
            }
            return super.newObject(vm, owner, signature, args);
        }

        @Override
        public DvmObject<?> callStaticObjectMethod(
                BaseVM vm, DvmClass owner, String signature, VarArg args) {
            if (signature.equals("com/alibaba/wireless/security/mainplugin/SecurityGuardMainPlugin"
                    + "->getMainPluginClassLoader()Ljava/lang/ClassLoader;")) {
                // Original onPluginLoaded assigns sClassLoader before System.loadLibrary.
                return loader;
            }
            return super.callStaticObjectMethod(vm, owner, signature, args);
        }

        @Override
        public DvmObject<?> callObjectMethod(
                BaseVM vm, DvmObject<?> object, String signature, VarArg args) {
            if (object == loader && signature.equals(
                    "java/lang/ClassLoader->loadClass(Ljava/lang/String;)Ljava/lang/Class;")) {
                return loadClass(vm, args.getObjectArg(0));
            }
            return super.callObjectMethod(vm, object, signature, args);
        }

        @Override
        public DvmObject<?> callObjectMethodV(
                BaseVM vm, DvmObject<?> object, String signature, VaList args) {
            if (object == loader && signature.equals(
                    "java/lang/ClassLoader->loadClass(Ljava/lang/String;)Ljava/lang/Class;")) {
                return loadClass(vm, args.getObjectArg(0));
            }
            return super.callObjectMethodV(vm, object, signature, args);
        }
    }

    public static void main(String[] args) throws Exception {
        if (args.length < 1 || args.length > 2
                || (args.length == 2 && !args[1].equals("--static-store"))) {
            throw new IllegalArgumentException(
                "Usage: NativeLoadProbe /absolute/path/damai-9.0.35.apk [--static-store]");
        }
        Path apk = Path.of(args[0]).toAbsolutePath();
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        try (InputStream input = Files.newInputStream(apk)) {
            byte[] buffer = new byte[65536];
            for (int count; (count = input.read(buffer)) != -1;) {
                digest.update(buffer, 0, count);
            }
        }
        String actual = HexFormat.of().formatHex(digest.digest());
        if (!actual.equals(APK_SHA256)) {
            throw new IllegalArgumentException("Original APK SHA-256 mismatch: " + actual);
        }
        Path work = Files.createTempDirectory("damai-native-load-");
        Path library = work.resolve("libsgmainso-6.8.260704.so");
        try (ZipFile zip = new ZipFile(apk.toFile());
             InputStream input = zip.getInputStream(zip.getEntry(LIBRARY))) {
            Files.copy(input, library);
        }
        Path plugin = work.resolve("sgmain.apk");
        try (ZipFile zip = new ZipFile(apk.toFile());
             InputStream input = zip.getInputStream(zip.getEntry("lib/armeabi-v7a/libsgmain.so"))) {
            Files.copy(input, plugin);
        }
        System.out.println("APK_SHA256=" + actual);
        System.out.println("LIBRARY_MEMBER=" + LIBRARY);
        System.out.println("WORK_DIR=" + work);
        String phase = "emulator_creation";
        try (AndroidEmulator emulator = AndroidEmulatorBuilder.for32Bit()
                .setProcessName("cn.damai")
                .setRootDir(work.resolve("rootfs").toFile())
                .addBackendFactory(new Unicorn2Factory(true))
                .build()) {
            // Bounds each emulated call; the outer process should also have a deadline.
            emulator.setTimeout(TimeUnit.SECONDS.toMicros(10));
            emulator.getMemory().setLibraryResolver(new AndroidResolver(23));
            VM vm = emulator.createDalvikVM(apk.toFile());
            // Unsupported Android APIs fail explicitly; no device properties are fabricated.
            PluginJni pluginJni = new PluginJni(vm, plugin);
            vm.setJni(pluginJni);
            vm.setVerbose(true);
            phase = "elf_load_and_initializers";
            System.out.println("PHASE=" + phase);
            DalvikModule module = vm.loadLibrary(library.toFile(), true);
            if (module.getModule().findSymbolByName("JNI_OnLoad", false) == null) {
                throw new IllegalStateException("Original library has no exported JNI_OnLoad");
            }
            phase = "jni_onload";
            System.out.println("PHASE=" + phase);
            module.callJNI_OnLoad(emulator);
            phase = "native_registration_lookup";
            System.out.println("PHASE=" + phase);
            var entry = vm.resolveClass("com/taobao/wireless/security/adapter/JNICLibrary")
                .findNativeFunction(emulator,
                    "doCommandNative(I[Ljava/lang/Object;)Ljava/lang/Object;");
            System.out.println("REGISTERED_NATIVE_ENTRY=" + entry);
            if (args.length == 2) {
                phase = "static_store_index_0_without_android_initialization";
                System.out.println("PHASE=" + phase);
                // Original C0136.getAppKeyByIndex: exact read-only command and argument order.
                DvmObject<?> value = vm.resolveClass("com/taobao/wireless/security/adapter/JNICLibrary")
                    .callStaticJniMethodObject(emulator,
                        "doCommandNative(I[Ljava/lang/Object;)Ljava/lang/Object;", 10602,
                        new ArrayObject(DvmInteger.valueOf(vm, 0), new StringObject(vm, "")));
                if (pluginJni.sdkFailure != null) {
                    throw pluginJni.sdkFailure;
                }
                if (value == null) {
                    throw new IllegalStateException(
                        "Static store returned null; no Android Context/plugin initialization was performed");
                }
                System.out.println("STATIC_STORE_VALUE=" + value.getValue());
            }
            System.out.println("RESULT=JNI_REGISTRATION_OBSERVED_NOT_SIGNING_SUCCESS");
        } catch (Throwable error) {
            System.err.println("FAILED_PHASE=" + phase);
            throw error;
        }
    }
}
