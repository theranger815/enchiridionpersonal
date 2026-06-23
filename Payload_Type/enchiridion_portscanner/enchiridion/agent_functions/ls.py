from mythic_container.MythicCommandBase import *
from mythic_container.MythicRPC import *


class LsArguments(TaskArguments):
    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = [
            CommandParameter(
                name="path",
                cli_name="path",
                display_name="Path to list files from.",
                type=ParameterType.String,
                default_value=".",
                description="Path of file or folder on the current system to list",
                parameter_group_info=[
                    ParameterGroupInfo(
                        required=False, group_name="Default", ui_position=1
                    )
                ],
            )
        ]

    async def parse_dictionary(self, dictionary_arguments):
        logger.info(dictionary_arguments)
        logger.info(self.tasking_location)
        self.load_args_from_dictionary(dictionary_arguments)
        if "host" in dictionary_arguments:
            if "full_path" in dictionary_arguments:
                path = dictionary_arguments["full_path"]
                if not path.startswith("/"):
                    path = "/" + path
                self.add_arg("path", path)
            elif "path" in dictionary_arguments:
                path = dictionary_arguments["path"]
                if not path.startswith("/"):
                    path = "/" + path
                self.add_arg("path", path)
            elif "file" in dictionary_arguments:
                self.add_arg("path", "/" + dictionary_arguments["file"].lstrip("/"))
            else:
                logger.info("unknown dictionary args")
        else:
            if (
                "path" not in dictionary_arguments
                or dictionary_arguments["path"] is None
            ):
                self.add_arg("path", ".")

    async def parse_arguments(self):
        # Check if named parameters were defined
        cli_names = [arg.cli_name for arg in self.args if arg.cli_name is not None]
        if any(
            [
                self.raw_command_line.startswith(f"-{cli_name} ")
                for cli_name in cli_names
            ]
        ) or any([f" -{cli_name} " in self.raw_command_line for cli_name in cli_names]):
            args = json.loads(self.command_line)
        # Freeform unmatched arguments
        else:
            args = {"path": "."}
            if len(self.raw_command_line) > 0:
                args["path"] = self.raw_command_line
        self.load_args_from_dictionary(args)


class LsCommand(CommandBase):
    cmd = "ls"
    needs_admin = False
    help_cmd = "ls <path>"
    description = "Uses builtin library/system calls to get listing of a provided path file or directory"
    version = 1
    author = "@blackgazzelle"
    attackmapping = ["T1083"]
    supported_ui_features = ["file_browser:list"]
    argument_class = LsArguments
    attributes = CommandAttributes(suggested_command=True)
    browser_script = BrowserScript(
        script_name="ls_new", author="@its_a_feature_", for_new_ui=True
    )

    async def create_go_tasking(
        self, taskData: PTTaskMessageAllData
    ) -> PTTaskCreateTaskingMessageResponse:
        response = PTTaskCreateTaskingMessageResponse(
            TaskID=taskData.Task.ID,
            Success=True,
        )
        path = taskData.args.get_arg("path")
        if not path:
            path = "."
        response.DisplayParams = path
        taskData.args.add_arg("host", taskData.Callback.Host)
        return response

    async def process_response(
        self, task: PTTaskMessageAllData, response: any
    ) -> PTTaskProcessResponseMessageResponse:
        resp = PTTaskProcessResponseMessageResponse(TaskID=task.Task.ID, Success=True)
        return resp
