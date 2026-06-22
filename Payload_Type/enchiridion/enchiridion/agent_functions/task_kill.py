from mythic_container.MythicCommandBase import *
from mythic_container.PayloadBuilder import *


class TaskKillArguments(TaskArguments):
    def __init__(self, command_line, **kwargs):
        super().__init__(command_line, **kwargs)
        self.args = [
            CommandParameter(
                name="task_id",
                type=ParameterType.String,
                description="Agent task ID to kill",
                parameter_group_info=[ParameterGroupInfo(required=True)],
            )
        ]

    async def parse_arguments(self):
        self.add_arg("task_id", self.command_line)

    async def parse_dictionary(self, dictionary):
        self.load_args_from_dictionary(dictionary)


class TaskKillCommand(CommandBase):
    cmd = "task_kill"
    needs_admin = False
    help_cmd = "task_kill <task_id>"
    description = "Kills a running task by agent task ID. Use the skull icon in the UI to invoke automatically."
    version = 1
    author = "@blackgazzelle"
    supported_ui_features = ["task:job_kill"]
    argument_class = TaskKillArguments
    attributes = CommandAttributes(suggested_command=True)
    script_only = False

    async def create_go_tasking(
        self, taskData: PTTaskMessageAllData
    ) -> PTTaskCreateTaskingMessageResponse:
        response = PTTaskCreateTaskingMessageResponse(
            TaskID=taskData.Task.ID,
            Success=True,
        )
        task_id = taskData.args.get_arg("task_id")
        if task_id:
            response.DisplayParams = task_id
        return response

    async def process_response(
        self, task: PTTaskMessageAllData, response: any
    ) -> PTTaskProcessResponseMessageResponse:
        pass
