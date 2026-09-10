from aiogram.fsm.state import State, StatesGroup

class CreateUserStates(StatesGroup):
    waiting_for_interface = State()
    waiting_for_username = State()

class CreateConfigStates(StatesGroup):
    waiting_for_user_selection = State()
    waiting_for_label = State()
