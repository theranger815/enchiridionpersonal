from mythic_container.MythicCommandBase import *
from mythic_container.PayloadBuilder import *


class PscanArguments(TaskArguments):
    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = [
            CommandParameter(
                name="host",
                type=ParameterType.String,
                description="Host/IP to scan",
                parameter_group_info=[ParameterGroupInfo(required=True)],
            ),
            CommandParameter(
                name="port",
                type=ParameterType.String,
                description="Ports to scan",
                parameter_group_info=[ParameterGroupInfo(required=True)],
            ),
            CommandParameter(
                name="mode",
                type=ParameterType.String,
                description="Scan type (syn/banner)",
                parameter_group_info=[ParameterGroupInfo(required=True)],
            ),
        ]

    # NOTE: This shi was wrong lmao
    async def parse_arguments(self):
        self.load_args_from_json_string(self.command_line)


class PscanCommand(CommandBase):
    cmd = "pscan"
    needs_admin = False
    help_cmd = "pscan <mode> <host> <port>"
    description = "Scans ports on specified host"
    version = 1
    author = "@ITookAShris"
    # supported_ui_features = ["file_browser:download"]
    argument_class = PscanArguments
    attributes = CommandAttributes(suggested_command=True)
    script_only = False

    async def create_go_tasking(
        self, taskData: PTTaskMessageAllData
    ) -> PTTaskCreateTaskingMessageResponse:
        response = PTTaskCreateTaskingMessageResponse(
            TaskID=taskData.Task.ID,
            Success=True,
        )
        return response

    async def process_response(
        self, task: PTTaskMessageAllData, response: any
    ) -> PTTaskProcessResponseMessageResponse:
        pass
