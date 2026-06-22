from mythic_container.MythicCommandBase import *
from mythic_container.PayloadBuilder import *


class UploadArguments(TaskArguments):
    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = [
            CommandParameter(
                name="file",
                type=ParameterType.File,
                description="File to upload to the target",
                parameter_group_info=[ParameterGroupInfo(required=True)],
            ),
            CommandParameter(
                name="remote_path",
                type=ParameterType.String,
                description="Destination path on the target (absolute or relative)",
                parameter_group_info=[ParameterGroupInfo(required=True)],
            ),
        ]

    async def parse_arguments(self):
        self.load_args_from_json_string(self.command_line)

    async def parse_dictionary(self, dictionary):
        if "host" in dictionary:
            # Triggered from file browser — path is the current directory
            self.add_arg("remote_path", dictionary.get("path", "") + "/" + dictionary.get("file", ""))
        self.load_args_from_dictionary(dictionary)


class UploadCommand(CommandBase):
    cmd = "upload"
    needs_admin = False
    help_cmd = "upload"
    description = "Uploads a file from the operator to the agent."
    version = 1
    author = "@blackgazzelle"
    supported_ui_features = ["file_browser:upload"]
    argument_class = UploadArguments
    attributes = CommandAttributes(suggested_command=True)
    script_only = False

    async def create_go_tasking(
        self, taskData: PTTaskMessageAllData
    ) -> PTTaskCreateTaskingMessageResponse:
        response = PTTaskCreateTaskingMessageResponse(
            TaskID=taskData.Task.ID,
            Success=True,
        )
        remote_path = taskData.args.get_arg("remote_path")
        if remote_path:
            response.DisplayParams = remote_path
        return response

    async def process_response(
        self, task: PTTaskMessageAllData, response: any
    ) -> PTTaskProcessResponseMessageResponse:
        pass
