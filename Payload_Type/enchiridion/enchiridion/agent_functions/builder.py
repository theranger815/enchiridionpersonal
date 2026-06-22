import asyncio
import os
import pathlib
import tempfile
from shutil import copytree

from mythic_container.MythicCommandBase import *
from mythic_container.MythicRPC import *
from mythic_container.PayloadBuilder import *


class EnchiridionAgent(PayloadType):
    name = "enchiridion"
    file_extension = ""
    author = "@blackgazzelle"
    supported_os = [SupportedOS.Linux]
    wrapper = False
    wrapped_payloads = []
    note = """This payload uses C to execute on Linux/Windows systems"""
    supports_dynamic_loading = True
    semver = "0.1.0"
    c2_profiles = ["http", "websocket"]
    mythic_encrypts = True
    translation_container = None
    build_parameters = [
        BuildParameter(
            name="Build Type",
            parameter_type=BuildParameterType.ChooseOne,
            choices=["Release", "Debug"],
            default_value="Release",
            description="Debug or Release build",
            group_name="Build type options",
        ),
        BuildParameter(
            name="NUMTHREADS",
            parameter_type=BuildParameterType.Number,
            default_value=1,
            description="Number of threads to use as worker",
            group_name="Build type options",
        ),
    ]

    agent_path = pathlib.Path(".") / "enchiridion"
    agent_icon_path = agent_path / "agent_functions" / "enchiridion.svg"
    agent_code_path = agent_path / "agent_code"

    build_steps = [
        BuildStep(
            step_name="Gathering Files",
            step_description="Making sure all commands have backing files on disk",
        ),
        BuildStep(
            step_name="Configuring", step_description="Stamping in configuration values"
        ),
        BuildStep(step_name="Compiling", step_description="Compiling with musl"),
    ]

    async def build(self) -> BuildResponse:
        # this function gets called to create an instance of your payload
        resp = BuildResponse(status=BuildStatus.Success)
        Config = {
            "payload_uuid": self.uuid,
            "callback_host": "",
            "USER_AGENT": "",
            "httpMethod": "POST",
            "post_uri": "",
            "headers": [],
            "callback_port": 80,
            "ssl": False,
            "proxyEnabled": False,
            "proxy_host": "",
            "proxy_user": "",
            "proxy_pass": "",
        }
        stdout_err = ""
        c2_impls = ""
        profile_name = "http"
        for index, c2 in enumerate(self.c2info):
            profile = c2.get_c2profile()
            profile_name = profile["name"]
            if index == 0:
                c2_impls += profile_name
            else:
                c2_impls += ";" + profile_name

            for key, val in c2.get_parameters_dict().items():
                Config[key] = val
            break

        cb_host = Config.get("callback_host", "")
        if "https://" in cb_host or "wss://" in cb_host:
            Config["ssl"] = True

        Config["callback_host"] = (
            cb_host
            .replace("wss://", "")
            .replace("ws://", "")
            .replace("https://", "")
            .replace("http://", "")
        )

        # Endpoint key differs by profile: websocket uses ENDPOINT_REPLACE, http uses post_uri.
        if profile_name == "websocket":
            Config["post_uri"] = Config.get("ENDPOINT_REPLACE", Config.get("post_uri", ""))

        if Config.get("proxy_host", "") != "":
            Config["proxyEnabled"] = True
        # create the payload
        await SendMythicRPCPayloadUpdatebuildStep(
            MythicRPCPayloadUpdateBuildStepMessage(
                PayloadUUID=self.uuid,
                StepName="Gathering Files",
                StepStdout="Found all files for payload",
                StepSuccess=True,
            )
        )
        agent_build_path = tempfile.TemporaryDirectory(suffix=self.uuid)
        copytree(self.agent_code_path, agent_build_path.name, dirs_exist_ok=True)

        # Derive encryption mode from C2 profile parameters.
        # AESPSK is a crypto_type parameter; Mythic returns it as a dict:
        #   {"value": "none"|"aes256_hmac"|"aes256_hmac_eke", "enc_key": <b64>|None, ...}
        # encrypted_exchange_check is a ChooseOne ("T"/"F") or bool.
        aespsk_raw = Config.get("AESPSK", {}) or {}
        if isinstance(aespsk_raw, dict):
            aespsk_value = (aespsk_raw.get("value", "none") or "none").lower()
            aespsk = aespsk_raw.get("enc_key", "") or ""
        else:
            aespsk_value = str(aespsk_raw).lower()
            aespsk = str(aespsk_raw) if aespsk_value != "none" else ""

        ec = Config.get("encrypted_exchange_check", False)
        encrypted_exchange = ec is True or str(ec).upper() in ("T", "TRUE")

        if encrypted_exchange or aespsk_value == "aes256_hmac_eke":
            enc_flag = "EKE"
        elif aespsk_value != "none" and aespsk:
            enc_flag = "STATIC_KEY"
        else:
            enc_flag = "NONE"

        with open(agent_build_path.name + "/include/config.h", "r+") as f:
            content = f.read()
            content = content.replace("%UUID%", Config["payload_uuid"])
            content = content.replace("%HOSTNAME%", Config["callback_host"])
            content = content.replace("%ENDPOINT%", Config["post_uri"])
            if not Config["ssl"]:
                content = content.replace("SSL_ENABLED 1", "SSL_ENABLED 0")
            content = content.replace("PORT 80", f"PORT {str(Config['callback_port'])}")
            content = content.replace(
                "SLEEP_TIME 60", f"SLEEP_TIME {str(Config['callback_interval'])}"
            )
            content = content.replace("%USERAGENT%", Config["USER_AGENT"])
            content = content.replace("%PROXYURL%", Config.get("proxy_host", ""))
            if Config["proxyEnabled"]:
                content = content.replace("PROXYENABLED true", "PROXYENABLED true")
            else:
                content = content.replace("PROXYENABLED true", "PROXYENABLED false")
            content = content.replace(
                "NUM_THREADS 1", f"NUM_THREADS {self.get_parameter('NUMTHREADS')}"
            )

            if enc_flag in ("STATIC_KEY", "EKE"):
                content = content.replace("%STATIC_KEY%", aespsk)
            else:
                content = content.replace("%STATIC_KEY%", "")
            content = content.replace("%RSA_PUB_KEY%", "")

            f.seek(0)
            f.write(content)
            f.truncate()

        await SendMythicRPCPayloadUpdatebuildStep(
            MythicRPCPayloadUpdateBuildStepMessage(
                PayloadUUID=self.uuid,
                StepName="Applying configuration",
                StepStdout=f"Encryption mode: {enc_flag}",
                StepSuccess=True,
            )
        )

        _ext_cache = "/opt/enchiridion/ext_cache"
        _cache_args = (
            f" -DMUSL_ROOT={_ext_cache}/musl-toolchain"
            f" -DPREBUILT_EXTERNAL_ROOT={_ext_cache}/external"
        ) if os.path.isdir(_ext_cache) else ""

        build_command = (
            f"cmake -S . -B build"
            f" -DCMAKE_BUILD_TYPE={self.get_parameter('Build Type')}"
            f" -DCMAKE_TOOLCHAIN_FILE=cmake/musl-toolchain.cmake"
            f"{_cache_args}"
            f" -DC2_IMPL={c2_impls}"
            f" -DENCRYPTION_MODE={enc_flag}"
            f" && cmake --build build -j$(nproc)"
        )
        proc = await asyncio.create_subprocess_shell(
            build_command,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            cwd=agent_build_path.name,
        )

        stdout, stderr = await proc.communicate()
        stdout = stdout.decode(errors="ignore") if isinstance(stdout, bytes) else stdout
        stderr = stderr.decode(errors="ignore") if isinstance(stderr, bytes) else stderr

        if proc.returncode != 0:
            await SendMythicRPCPayloadUpdatebuildStep(
                MythicRPCPayloadUpdateBuildStepMessage(
                    PayloadUUID=self.uuid,
                    StepName="Compiling",
                    StepStdout=stdout,
                    StepStderr=stderr,
                    StepSuccess=False,
                )
            )
            resp.status = BuildStatus.Error
            resp.error_message = stderr
            return resp

        await SendMythicRPCPayloadUpdatebuildStep(
            MythicRPCPayloadUpdateBuildStepMessage(
                PayloadUUID=self.uuid,
                StepName="Compiling",
                StepStdout="Successfully compiled",
                StepStderr=stderr,
                StepSuccess=True,
            )
        )

        filename = agent_build_path.name + "/build/enchiridion"
        resp.payload = open(filename, "rb").read()

        return resp
