from mythic_container.MythicCommandBase import *
from mythic_container.MythicRPC import *


class SocksArguments(TaskArguments):
    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = [
            CommandParameter(
                name="action",
                type=ParameterType.ChooseOne,
                choices=["start", "stop", "flush"],
                default_value="start",
                description="Start or stop the SOCKS5 proxy, or flush existing connections.",
                parameter_group_info=[ParameterGroupInfo(ui_position=1)],
            ),
            CommandParameter(
                name="port",
                type=ParameterType.Number,
                default_value=7000,
                description="Local port on the Mythic server to listen on.",
                parameter_group_info=[ParameterGroupInfo(ui_position=2)],
            ),
            CommandParameter(
                name="username",
                type=ParameterType.String,
                default_value="",
                description="Optional SOCKS5 username for authentication.",
                parameter_group_info=[ParameterGroupInfo(required=False, ui_position=4)],
            ),
            CommandParameter(
                name="password",
                type=ParameterType.String,
                default_value="",
                description="Optional SOCKS5 password for authentication.",
                parameter_group_info=[ParameterGroupInfo(required=False, ui_position=5)],
            ),
        ]

    async def parse_arguments(self):
        self.load_args_from_json_string(self.command_line)

    async def parse_dictionary(self, dictionary_arguments):
        self.load_args_from_dictionary(dictionary_arguments)


class SocksCommand(CommandBase):
    cmd = "socks"
    needs_admin = False
    help_cmd = "socks (start|stop|flush) [port]"
    description = "Start or stop a SOCKS5 proxy tunneled through the C2 channel."
    version = 1
    author = "@blackgazzelle"
    attackmapping = ["T1572"]
    argument_class = SocksArguments
    attributes = CommandAttributes(supported_os=[SupportedOS.Linux])

    async def create_go_tasking(
        self, taskData: MythicCommandBase.PTTaskMessageAllData
    ) -> MythicCommandBase.PTTaskCreateTaskingMessageResponse:
        response = MythicCommandBase.PTTaskCreateTaskingMessageResponse(
            TaskID=taskData.Task.ID,
            Success=True,
        )

        action = taskData.args.get_arg("action")
        port = taskData.args.get_arg("port")
        username = taskData.args.get_arg("username") or ""
        password = taskData.args.get_arg("password") or ""

        if action == "start":
            resp = await SendMythicRPCProxyStartCommand(
                MythicRPCProxyStartMessage(
                    TaskID=taskData.Task.ID,
                    PortType=CALLBACK_PORT_TYPE_SOCKS,
                    LocalPort=port,
                    Username=username,
                    Password=password,
                )
            )
            response.Success = resp.Success
            if not resp.Success:
                response.Error = resp.Error
        elif action == "stop":
            resp = await SendMythicRPCProxyStopCommand(
                MythicRPCProxyStopMessage(
                    TaskID=taskData.Task.ID,
                    PortType=CALLBACK_PORT_TYPE_SOCKS,
                    Port=port,
                    Username=username,
                    Password=password,
                )
            )
            response.Success = resp.Success
            if not resp.Success:
                response.Error = resp.Error
        # "flush" requires no Mythic RPC call — handled entirely in the C agent

        return response

    async def process_response(
        self, task: PTTaskMessageAllData, response: any
    ) -> PTTaskProcessResponseMessageResponse:
        return PTTaskProcessResponseMessageResponse(TaskID=task.Task.ID, Success=True)
