from mythic_container.MythicCommandBase import *
from mythic_container.PayloadBuilder import *


class DownloadArguments(TaskArguments):
    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = [
            CommandParameter(
                name="path",
                type=ParameterType.String,
                description="Path of file to download",
                parameter_group_info=[ParameterGroupInfo(required=True)],
            )
        ]

    async def parse_arguments(self):
        self.add_arg("path", self.command_line)

    async def parse_dictionary(self, dictionary):
        if "host" in dictionary:
            # then this came from the file browser
            self.add_arg("path", dictionary["path"] + "/" + dictionary["file"])
            self.add_arg("file_browser", type=ParameterType.Boolean, value=True)
        else:
            self.load_args_from_dictionary(dictionary)


class DownloadCommand(CommandBase):
    cmd = "download"
    needs_admin = False
    help_cmd = "download <path>"
    description = "Downloads a file from the agent."
    version = 1
    author = "@blackgazzelle"
    supported_ui_features = ["file_browser:download"]
    argument_class = DownloadArguments
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
