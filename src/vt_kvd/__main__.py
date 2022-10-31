# dependencies
import dearpygui.dearpygui as dpg
# standard libraries
from time import sleep
import argparse
import sys
import traceback
import typing
# from typing import Tuple, Optional, Hashable, TypeVar

from . import applicationPath, settingsFile
from .version import __version__, __copyright__
from .theme import (
    getGlobalFont,
    getGlobalTheme,
    getErrorTheme,
    getWindowTheme,
    getCellHighlightedTheme,
    getCellDefaultTheme,
    styleHorizontalPadding,
    styleScrollbarWidth
)

debugMode: bool = False

mainWindowID: str = "main-window"

# Dear PyGui (and Dear ImGui) has a limitation of 64 columns in a table
# https://dearpygui.readthedocs.io/en/latest/documentation/tables.html
# https://github.com/ocornut/imgui/issues/2957#issuecomment-758136035
# https://github.com/ocornut/imgui/pull/4876
dpgColumnsMax: int = 64

windowMinWidth: int = 900


def showDPGabout() -> None:
    # dpg.hide_item("aboutWindow")
    dpg.show_about()


def main() -> None:
    global debugMode

    argParser = argparse.ArgumentParser(
        prog="vt-kvd",
        description=" ".join((
            f"%(prog)s\n{__copyright__}\nA",
            "VirusTotal GUI client"
        )),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        allow_abbrev=False
    )
    argParser.add_argument(
        "--version",
        action="version",
        version=f"%(prog)s {__version__}"
    )
    argParser.add_argument(
        "--debug",
        action='store_true',
        help="enable debug/dev mode (default: %(default)s)"
    )
    cliArgs = argParser.parse_args()
    # print(cliArgs)

    debugMode = cliArgs.debug

    dpg.create_context()

    dpg.configure_app(init_file=settingsFile)

    # dpg.set_frame_callback(2, callback=updateGeometry)
    # dpg.set_viewport_resize_callback(callback=updateGeometry)
    dpg.set_exit_callback(callback=lambda: dpg.save_init_file(settingsFile))

    #
    # --- main window
    #
    with dpg.window(tag=mainWindowID):
        #
        # --- menu
        #
        with dpg.menu_bar():
            with dpg.menu(label="File"):
                # dpg.add_menu_item(
                #     tag="menuExecuteQuery",
                #     label="Execute query",
                #     shortcut="Cmd/Ctrl + R",
                #     callback=executeQuery
                # )
                dpg.add_spacer()
                dpg.add_separator()
                dpg.add_spacer()
                dpg.add_menu_item(
                    tag="menuSaveFile",
                    label="Save results to pickle...",
                    enabled=False,
                    callback=lambda: dpg.show_item("dialogSaveFile")
                )
                dpg.add_spacer()
                dpg.add_separator()
                dpg.add_spacer()
                dpg.add_menu_item(
                    label="Exit",
                    callback=lambda: dpg.stop_dearpygui()
                )

            # with dpg.menu(label="Settings"):
            #     dpg.add_menu_item(
            #         label="Setting 1",
            #         callback=lambda: print("ololo"),
            #         check=True
            #     )
            #     dpg.add_menu_item(
            #         label="Setting 2",
            #         callback=lambda: print("ololo")
            #     )

            if debugMode:
                with dpg.menu(label="Dev"):
                    dpg.add_menu_item(
                        label="Performance metrics",
                        callback=lambda: dpg.show_metrics()
                    )
                    dpg.add_menu_item(
                        label="Items registry",
                        callback=lambda: dpg.show_item_registry()
                    )
                    dpg.add_menu_item(
                        label="Styling",
                        callback=lambda: dpg.show_style_editor()
                    )
                    dpg.add_menu_item(
                        label="ImGui demo",
                        callback=lambda: dpg.show_imgui_demo()
                    )

            with dpg.menu(label="Help"):
                dpg.add_menu_item(
                    label="About...",
                    callback=lambda: dpg.show_item("aboutWindow")
                )
        #
        # -- contents
        #
        dpg.add_input_text(
            tag="serviceURL",
            hint="TAP service",
            width=-1
        )
        # dpg.add_input_text(
        #     tag=queryTextID,
        #     # FIXME doesn't work (yet)
        #     # https://github.com/hoffstadt/DearPyGui/issues/1519
        #     hint="ADQL query",
        #     default_value="".join((
        #         "SELECT TOP 11 *\n",
        #         "FROM some_table\n",
        #         "WHERE some_thing = 1"
        #     )),
        #     width=-1,
        #     height=350,
        #     multiline=True,
        #     tab_input=True
        # )
        # dpg.add_button(
        #     tag="btnExecuteQuery",
        #     label="Execute query",
        #     callback=executeQuery
        # )
        dpg.add_loading_indicator(
            tag="loadingAnimation",
            radius=2,
            speed=3,
            indent=10,
            show=False
        )

        dpg.add_spacer()

        dpg.add_text(
            tag="errorMessage",
            default_value="Error",
            # https://github.com/hoffstadt/DearPyGui/issues/1275
            wrap=windowMinWidth-50,
            show=False
        )

        with dpg.group(tag="resultsGroup", show=False):
            dpg.add_text(default_value="Query results:")
            with dpg.table(tag="resultsTable"):
                dpg.add_table_column(label="Results")
    #
    # --- save file dialog
    #
    # with dpg.file_dialog(
    #     id="dialogSaveFile",
    #     directory_selector=False,
    #     width=800,
    #     height=600,
    #     modal=True,
    #     show=False,
    #     callback=saveResultsToPickle
    # ):
    #     dpg.add_file_extension(".pkl", color=(30, 225, 0))
    #
    # --- error dialog
    #
    # with dpg.window(
    #     tag="errorDialog",
    #     label="Error",
    #     modal=True,
    #     show=False,
    #     width=300
    # ):
    #     dpg.add_text(
    #         tag="errorDialogText",
    #         default_value="Unknown error"
    #     )
    #     dpg.add_button(
    #         label="Close",
    #         callback=lambda: dpg.hide_item("errorDialog")
    #     )
    #     dpg.add_spacer(height=2)
    #
    # --- about window
    #
    with dpg.window(
        tag="aboutWindow",
        label="About application",
        # https://github.com/retifrav/tap-adql-sandbox/issues/6
        # modal=True,
        min_size=(780, 380),
        show=False
    ):
        dpg.add_text(
            "".join((
                "A VirusTotal ",
                "GUI client."
            ))
        )

        dpg.add_text(f"Version: {__version__}")

        dpg.add_text(
            "".join((
                "License: GPLv3\n",
                "Source code: https://github.com/retifrav/vt-kvd"
            ))
        )

        dpg.add_text(__copyright__)

        dpg.add_spacer()
        dpg.add_separator()
        dpg.add_spacer(height=5)
        with dpg.group(horizontal=True):
            dpg.add_text("Created with Dear PyGui")
            dpg.add_button(
                label="about that...",
                callback=showDPGabout
            )
        dpg.add_spacer(height=5)
        dpg.add_separator()
        dpg.add_spacer(height=10)
        dpg.add_button(
            label="Close",
            callback=lambda: dpg.hide_item("aboutWindow")
        )
        dpg.add_spacer(height=2)

    # themes/styles bindings
    dpg.bind_font(getGlobalFont())
    dpg.bind_theme(getGlobalTheme())
    dpg.bind_item_theme("errorMessage", getErrorTheme())
    dpg.bind_item_theme("aboutWindow", getWindowTheme())
    # dpg.bind_item_theme("errorDialog", getWindowTheme())
    # dpg.bind_item_theme("errorDialogText", getErrorTheme())

    # keyboard shortcuts
    # with dpg.handler_registry():
    #     # --- for the query text
    #     # Mac OS | Control
    #     dpg.add_key_press_handler(341, callback=keyPressCallback)
    #     # Mac OS | left Command
    #     dpg.add_key_press_handler(343, callback=keyPressCallback)
    #     # Mac OS | right Command
    #     dpg.add_key_press_handler(347, callback=keyPressCallback)
    #     # Linux | right Ctrl?
    #     dpg.add_key_press_handler(345, callback=keyPressCallback)
    #     # Windows | left and right Ctrl
    #     dpg.add_key_press_handler(17, callback=keyPressCallback)

    # ---

    dpg.create_viewport(
        title="vt-kvd",
        width=1200,
        height=800,
        min_width=windowMinWidth,
        min_height=600
        #small_icon=str(applicationPath/"icons/planet-128.ico"),
        #large_icon=str(applicationPath/"icons/planet-256.ico")
    )

    dpg.setup_dearpygui()
    dpg.show_viewport()
    dpg.set_primary_window(mainWindowID, True)

    # things to do on application start
    #dpg.set_value("serviceURL", examplesList["padc-system-planets"]["serviceURL"])
    #dpg.set_value(queryTextID, examplesList["padc-system-planets"]["queryText"])

    dpg.start_dearpygui()

    dpg.destroy_context()


if __name__ == "__main__":
    main()
