# standard libraries
from time import sleep
import argparse
import sys
import traceback
import pathlib
import webbrowser
import typing
from typing import Optional, List
# dependencies
import dearpygui.dearpygui as dpg
from dearpygui.demo import show_demo
import pandas
import vt

from . import applicationPath, settingsFile
from .version import (
    __version__,
    __copyright__,
    __platform__
)
from .theme import (
    getGlobalFont,
    getGlobalTheme,
    getErrorTheme,
    getWindowTheme,
    getHighlightedTheme,
    getCellDefaultTheme,
    getHyperlinkTheme,
    styleHorizontalPadding,
    styleScrollbarWidth
)
from .utils import (
    getVirusTotalAPIkeyFromConfig,
    calculateSHAchecksum,
    findFilesToCheck,
    estimateDangerLevel
)

debugMode: bool = False
enableDirScan: bool = False
vtAPIkey: Optional[str] = None
vtAgent: str = f"vt-kvd/{__version__} {__platform__}"

vtClient = None

mainWindowID: str = "main-window"

repositoryURL: str = "https://github.com/retifrav/vt-kvd"
vtReportBaseURL: str = "https://www.virustotal.com/gui/file"

# Dear PyGui (and Dear ImGui) has a limitation of 64 columns in a table
# https://dearpygui.readthedocs.io/en/latest/documentation/tables.html
# https://github.com/ocornut/imgui/issues/2957#issuecomment-758136035
# https://github.com/ocornut/imgui/pull/4876
dpgColumnsMax: int = 64

windowMinWidth: int = 900

lastCheckResults: pandas.DataFrame = pandas.DataFrame()
runningCheck: bool = False


def applicationClosing():
    dpg.save_init_file(settingsFile)
    vtClient.close()


def add_hyperlink(text: str, address: str):
    b = dpg.add_button(
        label=text,
        callback=lambda: webbrowser.open(address)
    )
    dpg.bind_item_theme(b, getHyperlinkTheme())


def showDPGabout() -> None:
    dpg.hide_item("window_about")
    dpg.show_about()


def showLoading(isLoading: bool) -> None:
    global runningCheck

    if isLoading:
        dpg.hide_item("btn_runCheck")
        dpg.configure_item("menu_runCheck", enabled=False)
        dpg.show_item("loadingAnimation")
        runningCheck = True
    else:
        dpg.hide_item("loadingAnimation")
        dpg.show_item("btn_runCheck")
        dpg.configure_item("menu_runCheck", enabled=True)
        runningCheck = False


def getCurrentAPIquota() -> None:
    dpg.hide_item("errorMessageQuotas")
    dpg.set_value("errorMessageQuotas", "")
    dpg.hide_item("btn_getQuotas")
    dpg.show_item("loadingAnimationQuotas")

    try:
        quotas = vtClient.get_data(f"/users/{vtAPIkey}/overall_quotas")
        if quotas and quotas is not None:
            dpg.set_value(
                "cell_quotaHourly",
                "/".join((
                    str(quotas["api_requests_hourly"]["user"]["used"]),
                    str(quotas["api_requests_hourly"]["user"]["allowed"])
                ))
            )
            dpg.set_value(
                "cell_quotaDaily",
                "/".join((
                    str(quotas["api_requests_daily"]["user"]["used"]),
                    str(quotas["api_requests_daily"]["user"]["allowed"])
                ))
            )
            dpg.set_value(
                "cell_quotaMonthly",
                "/".join((
                    str(quotas["api_requests_monthly"]["user"]["used"]),
                    str(quotas["api_requests_monthly"]["user"]["allowed"])
                ))
            )
    except Exception as ex:
        errorMsg: str = "Couldn't get current quotas"
        print(f"[ERROR] {errorMsg}. {ex}", file=sys.stderr)
        if debugMode:
            traceback.print_exc(file=sys.stderr)
        dpg.set_value(
            "errorMessageQuotas",
            f"{errorMsg}. There might be more details in console/stderr."
        )
        dpg.show_item("errorMessageQuotas")

    dpg.hide_item("loadingAnimationQuotas")
    dpg.show_item("btn_getQuotas")


def showQuotaWindow() -> None:
    dpg.hide_item("menu_getAPIquota")
    dpg.show_item("window_apiQuota")
    getCurrentAPIquota()


def keyPressCallback(sender, app_data) -> None:
    # global runningCheck

    # print(sender, app_data)

    # dpg.is_item_focused
    if runningCheck:
        return

    if dpg.is_key_down(dpg.mvKey_R):
        runCheck()

    # if dpg.is_key_down(dpg.mvKey_O):
    #     dpg.show_item("dialogOpenPath")


def runCheck() -> None:
    global lastCheckResults
    # clear previously saved results
    lastCheckResults = pandas.DataFrame()

    dpg.hide_item("resultsGroup")
    if dpg.does_item_exist("resultsTable"):
        dpg.delete_item("resultsTable")
    dpg.hide_item("errorMessage")
    dpg.set_value("errorMessage", "")

    dpg.configure_item("menuSaveFile", enabled=False)
    showLoading(True)

    pathToCheckStr: str = dpg.get_value("input_pathToCheck").strip()
    if not pathToCheckStr:
        dpg.set_value(
            "errorMessage",
            "No path to check provided."
        )
        dpg.show_item("errorMessage")
        showLoading(False)
        return

    pathToCheck: pathlib.Path = pathlib.Path(pathToCheckStr)
    if not pathToCheck.exists():
        dpg.set_value(
            "errorMessage",
            "Provided path doesn't seem to exist."
        )
        dpg.show_item("errorMessage")
        showLoading(False)
        return
    if not pathToCheck.is_file() and not pathToCheck.is_dir():
        dpg.set_value(
            "errorMessage",
            "Provided path is neither file nor directory."
        )
        dpg.show_item("errorMessage")
        showLoading(False)
        return
    filesToCheck: List[pathlib.Path] = []
    if pathToCheck.is_dir():
        if not enableDirScan:
            dpg.set_value(
                "errorMessage",
                " ".join((
                    "Provided path is a directory and not a file.",
                    "Scanning directories is disabled by default.",
                    "If you would like to enable it, launch the application",
                    "with --enable-dir-scan. That will also require you",
                    "to have `libmagic` binary installed in the system."
                ))
            )
            dpg.show_item("errorMessage")
            showLoading(False)
            return
        print(
            " ".join((
                "\n[WARNING] Provided path is a directory.",
                "The application will try to find the suitable files",
                "by guessing their type based on magic numbers.",
                "This is not an absolutely reliable way,",
                "so it is recommended that you check the files",
                "of interest individually by explicitly providing",
                "their full paths one by one. Another thing to consider",
                "is that VirusTotal API has a quota for requests",
                "per day on standard free public accounts, so you can",
                "quickly exceed that amount by scanning directories",
                "instead of individual files"
            ))
        )
        try:
            filesToCheck = findFilesToCheck(pathToCheck, debugMode)
        except Exception as ex:
            errorMsg = "Couldn't scan the directory"
            print(f"[ERROR] {errorMsg}. {ex}", file=sys.stderr)
            if debugMode:
                traceback.print_exc(file=sys.stderr)
            dpg.set_value(
                "errorMessage",
                f"{errorMsg}. There might be more details in console/stderr."
            )
            dpg.show_item("errorMessage")
            showLoading(False)
            return
    else:
        filesToCheck.append(pathToCheck)
    if not filesToCheck:
        dpg.set_value(
            "errorMessage",
            "Did not find suitable files in the provided directory."
        )
        dpg.show_item("errorMessage")
        showLoading(False)
        return
    if debugMode:
        print("\n[DEBUG] Files to check:")
        for f in filesToCheck:
            print(f"- {f.as_posix()}")

    # TODO: if len(filesToCheck) > 10, ask for a confirmation

    try:
        idx: int = 0
        cnt = len(filesToCheck)
        print()
        for f in filesToCheck:
            print(f"Checking file {idx+1}/{cnt}...")
            checksum = calculateSHAchecksum(f)
            if debugMode:
                print(f"[DEBUG] SHA checksum: {checksum}")
            file = vtClient.get_object(f"/files/{checksum}")
            fileScanResults = pandas.DataFrame(
                {
                    "Name": (
                        str(file.meaningful_name)
                        if file.get("meaningful_name")
                        else f"{f.name}(*)"
                    ),
                    "Path": f.as_posix(),
                    "Type": "/".join((
                        str(file.type_tag),
                        str(file.type_description)
                    )),
                    "Count": str(file.times_submitted),
                    # "First time": str(file.first_submission_date),
                    "Last time": str(file.last_analysis_date),
                    # TODO: results-based coloring
                    "H/U/S/F/M/U": "/".join((
                        str(file.last_analysis_stats["harmless"]),
                        str(file.last_analysis_stats["type-unsupported"]),
                        str(file.last_analysis_stats["suspicious"]),
                        str(file.last_analysis_stats["failure"]),
                        str(file.last_analysis_stats["malicious"]),
                        str(file.last_analysis_stats["undetected"])
                    )),
                    "Danger": estimateDangerLevel(file.last_analysis_stats),
                    "Report": checksum
                },
                index=[idx]
            )
            lastCheckResults = pandas.concat(
                [lastCheckResults, fileScanResults]
            )
            idx += 1
    except vt.error.APIError as ex:
        errorMsg = " ".join((
            "Unknown error returned from VirusTotal API.",
            "There might be more details in console/stderr"
        ))
        if ex.code == "NotFoundError":
            errorMsg = " ".join((
                "This file hasn't been scanned at VirusTotal yet,",
                "so you might want to be the first one to do that",
                "and upload it for scanning"
            ))
        elif ex.code == "WrongCredentialsError":
            errorMsg = "Invalid, expired or revoked VirusTotal API key"
        elif ex.code == "QuotaExceededError":
            errorMsg = "You've exceeded your VirusTotal API quota"
        print(f"[ERROR] {errorMsg}. {ex}", file=sys.stderr)
        dpg.set_value("errorMessage", f"{errorMsg}.")
        dpg.show_item("errorMessage")
        showLoading(False)
        return
    except Exception as ex:
        errorMsg = "Couldn't check that path"
        print(f"[ERROR] {errorMsg}. {ex}", file=sys.stderr)
        if debugMode:
            traceback.print_exc(file=sys.stderr)
        dpg.set_value(
            "errorMessage",
            f"{errorMsg}. There might be more details in console/stderr."
        )
        dpg.show_item("errorMessage")
        showLoading(False)
        return

    rowsCount, columnsCount = lastCheckResults.shape
    try:
        with dpg.table(
            parent="resultsGroup",
            tag="resultsTable",
            header_row=True,
            resizable=True,
            borders_outerH=True,
            borders_innerV=True,
            borders_innerH=True,
            borders_outerV=True,
            clipper=True
            # no_host_extendX=True,
            # row_background=True,
            # freeze_rows=0,
            # freeze_columns=1,
            # scrollY=True,
            # policy=dpg.mvTable_SizingFixedFit,
            # scrollX=True
        ):
            dpg.add_table_column(label="#", init_width_or_weight=0.1)
            for header in (
                h for h in lastCheckResults.columns
                if h not in ["Path", "Danger"]
            ):
                dpg.add_table_column(
                    label=header,
                    tag=header.lower().replace(" ", "-"),
                    init_width_or_weight=(
                        0.3 if header in ["Count", "Report"]
                        else 1.0
                    )
                )
            with dpg.tooltip("name"):
                dpg.add_text(
                    "\n".join((
                        "(*) means that VirusTotal has no",
                        "`meaningful_name` property for this file,",
                        "and so local file name is used instead"
                    ))
                )
            with dpg.tooltip("count"):
                dpg.add_text(
                    "\n".join((
                        "How many times this file has been",
                        "submitted for checking"
                    ))
                )
            with dpg.tooltip("h/u/s/f/m/u"):
                dpg.add_text(
                    "\n".join((
                        "H - harmless",
                        "U - unsupported",
                        "S - suspicious",
                        "F - failure",
                        "M - malicious",
                        "U - undetected"
                    ))
                )
            for index, row in lastCheckResults.drop(
                columns=["Path", "Danger", "Report"]
            ).iterrows():
                # reveal_type(index)
                index = typing.cast(int, index)
                with dpg.table_row():
                    with dpg.table_cell():
                        dpg.add_text(default_value=f"{index+1}")
                    cellIndex = 1
                    for cell in row:
                        with dpg.table_cell():
                            cellID = f"cell-{index+1}-{cellIndex}"
                            dpg.add_text(
                                tag=cellID,
                                default_value=cell
                            )
                            dpg.bind_item_handler_registry(
                                cellID,
                                "cell-handler"
                            )
                            if cellIndex == 1:  # number
                                with dpg.tooltip(cellID):
                                    dpg.add_text(
                                        lastCheckResults.at[index, "Path"]
                                    )
                            if cellIndex == 5:  # analysis stats
                                if lastCheckResults.at[index, "Danger"] == 2:
                                    dpg.bind_item_theme(
                                        cellID,
                                        getErrorTheme()
                                    )
                                elif lastCheckResults.at[index, "Danger"] == 1:
                                    dpg.bind_item_theme(
                                        cellID,
                                        getHighlightedTheme()
                                    )
                        cellIndex += 1
                    with dpg.table_cell():
                        add_hyperlink(
                            "open",
                            "/".join((
                                vtReportBaseURL,
                                lastCheckResults.at[index, "Report"]
                            ))
                        )
    except Exception as ex:
        errorMsg = "Couldn't generate the results table"
        print(f"[ERROR] {errorMsg}. {ex}", file=sys.stderr)
        traceback.print_exc(file=sys.stderr)
        dpg.set_value(
            "errorMessage",
            f"{errorMsg}. There might be more details in console/stderr."
        )
        dpg.show_item("errorMessage")
        showLoading(False)
        return

    showLoading(False)
    dpg.show_item("resultsGroup")
    dpg.configure_item("menuSaveFile", enabled=True)


def saveResultsToFile(sender, app_data, user_data) -> None:
    # if debugMode:
    #     print(f"[DEBUG] {app_data}")
    # this check might be redundant,
    # as dialog window apparently performs it on its own
    resultsFileDir: pathlib.Path = pathlib.Path(app_data["current_path"])
    if not resultsFileDir.is_dir():
        print(
            f"[ERROR] The {resultsFileDir} directory does not exist",
            file=sys.stderr
        )
        return
    resultsFile: pathlib.Path = resultsFileDir / app_data["file_name"]
    try:
        errorMsg = "[NOT IMPLEMENTED] saving results to file"
        print(errorMsg, file=sys.stderr)
        dpg.set_value("errorMessage", f"{errorMsg}.")
        dpg.show_item("errorMessage")
    except Exception as ex:
        print(
            f"[ERROR] Couldn't save results to {resultsFile}: {ex}",
            file=sys.stderr
        )
        return


# def openPath(sender, app_data, user_data) -> None:
#     # if debugMode:
#     #     print(f"[DEBUG] {app_data}")
#     dpg.set_value("input_pathToCheck", app_data["file_path_name"])


def cellClicked(sender, app_data) -> None:
    # print(sender, app_data)

    # mouse right click
    if app_data[0] == 1:
        cellValue = dpg.get_value(app_data[1])
        # print(cellValue)
        dpg.set_clipboard_text(cellValue)
        dpg.set_value(app_data[1], "[copied]")
        itemTheme = dpg.get_item_theme(app_data[1])
        dpg.bind_item_theme(app_data[1], getHighlightedTheme())
        sleep(1)
        dpg.bind_item_theme(app_data[1], itemTheme)  # getCellDefaultTheme()
        dpg.set_value(app_data[1], cellValue)


def main() -> None:
    global debugMode
    global enableDirScan
    global vtAPIkey
    global vtClient

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
        "pathToCheck",
        nargs="?",
        type=pathlib.Path,
        metavar="/path/to/check",
        help="Path to what needs to be checked"
    )
    argParser.add_argument(
        "--version",
        action="version",
        version=f"%(prog)s {__version__}"
    )
    argParser.add_argument(
        "--enable-dir-scan",
        action='store_true',
        help="enable scanning directories (default: %(default)s)"
    )
    argParser.add_argument(
        "--debug",
        action='store_true',
        help="enable debug/dev mode (default: %(default)s)"
    )
    cliArgs = argParser.parse_args()
    # print(cliArgs)

    debugMode = cliArgs.debug
    enableDirScan = cliArgs.enable_dir_scan

    pathToCheck = cliArgs.pathToCheck
    if pathToCheck is not None and not pathToCheck.exists():
        raise SystemExit("[ERROR] Provided path doesn't seem to exist")

    dpg.create_context()

    dpg.configure_app(init_file=settingsFile)

    # dpg.set_frame_callback(2, callback=updateGeometry)
    # dpg.set_viewport_resize_callback(callback=updateGeometry)
    dpg.set_exit_callback(callback=applicationClosing)

    #
    # --- save file dialog
    #
    with dpg.file_dialog(
        id="dialogSaveFile",
        directory_selector=False,
        width=800,
        height=600,
        modal=True,
        show=False,
        callback=saveResultsToFile
    ):
        dpg.add_file_extension(".json", color=(30, 225, 0))
    #
    # --- open path dialog
    #
    # with dpg.file_dialog(
    #     tag="dialogOpenPath",
    #     directory_selector=enableDirScan,
    #     width=800,
    #     height=600,
    #     modal=True,
    #     show=False,
    #     callback=openPath
    # ):
    #     if not enableDirScan:
    #         dpg.add_file_extension(".*", color=(30, 225, 0))
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
        tag="window_about",
        label="About application",
        no_collapse=True,
        modal=True,
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

        dpg.add_text("License: GPLv3")
        with dpg.group(horizontal=True):
            dpg.add_text("Source code:")
            add_hyperlink(repositoryURL, repositoryURL)

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
            callback=lambda: dpg.hide_item("window_about")
        )
        dpg.add_spacer(height=2)
    #
    # --- VirusTotal API quota window
    #
    with dpg.window(
        tag="window_apiQuota",
        label="VirusTotal API quota",
        min_size=(400, 290),
        show=False,
        on_close=lambda: dpg.show_item("menu_getAPIquota")
    ):
        dpg.add_text("Your current API requests quotas:")
        with dpg.table(
            tag="quotaTable",
            header_row=True,
            # resizable=True,
            borders_outerH=True,
            borders_innerV=True,
            borders_innerH=True,
            borders_outerV=True
            # clipper=True,
            # row_background=True,
            # freeze_rows=0,
            # freeze_columns=1,
            # scrollY=True,
            # policy=dpg.mvTable_SizingFixedFit,
            # scrollX=True
        ):
            dpg.add_table_column(label="Quota")
            dpg.add_table_column(label="Used/Total")
            with dpg.table_row():
                with dpg.table_cell():
                    dpg.add_text(default_value="Hourly")
                with dpg.table_cell():
                    dpg.add_text(
                        tag="cell_quotaHourly",
                        default_value="?/?"
                    )
            with dpg.table_row():
                with dpg.table_cell():
                    dpg.add_text(default_value="Daily")
                with dpg.table_cell():
                    dpg.add_text(
                        tag="cell_quotaDaily",
                        default_value="?/?"
                    )
            with dpg.table_row():
                with dpg.table_cell():
                    dpg.add_text(default_value="Monthly")
                with dpg.table_cell():
                    dpg.add_text(
                        tag="cell_quotaMonthly",
                        default_value="?/?"
                    )
        dpg.add_spacer()
        dpg.add_button(
            tag="btn_getQuotas",
            label="Refresh",
            callback=getCurrentAPIquota
        )
        dpg.add_loading_indicator(
            tag="loadingAnimationQuotas",
            radius=2,
            speed=3,
            indent=10,
            show=False
        )
        dpg.add_text(
            tag="errorMessageQuotas",
            default_value="Error",
            # https://github.com/hoffstadt/DearPyGui/issues/1275
            wrap=350,  # window width - 50
            show=False
        )
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
                #     tag="menu_openPath",
                #     label="Open path...",
                #     shortcut="Cmd/Ctrl + O",
                #     callback=lambda: dpg.show_item("dialogOpenPath")
                # )
                dpg.add_menu_item(
                    tag="menu_runCheck",
                    label="Check the path",
                    shortcut="Cmd/Ctrl + R",
                    callback=runCheck
                )
                dpg.add_spacer()
                dpg.add_separator()
                dpg.add_spacer()
                dpg.add_menu_item(
                    tag="menuSaveFile",
                    label="Save results to file...",
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
                    dpg.add_spacer()
                    dpg.add_separator()
                    dpg.add_spacer()
                    dpg.add_menu_item(
                        label="Documentation",
                        callback=lambda: dpg.show_documentation()
                    )
                    dpg.add_spacer()
                    dpg.add_separator()
                    dpg.add_spacer()
                    dpg.add_menu_item(
                        label="Dear PyGui demo",
                        callback=lambda: show_demo()
                    )
                    dpg.add_menu_item(
                        label="Dear ImGui demo",
                        callback=lambda: dpg.show_imgui_demo()
                    )

            with dpg.menu(label="Help"):
                dpg.add_menu_item(
                    label="About...",
                    callback=lambda: dpg.show_item("window_about")
                )
                dpg.add_spacer()
                dpg.add_separator()
                dpg.add_spacer()
                dpg.add_menu_item(
                    tag="menu_getAPIquota",
                    label="Get VirusTotal API quota",
                    callback=showQuotaWindow
                )
        #
        # -- contents
        #
        dpg.add_input_text(
            tag="input_pathToCheck",
            hint="Path to check",
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
        dpg.add_button(
            tag="btn_runCheck",
            label="Check that",
            callback=runCheck
        )
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
            dpg.add_text(default_value="Results:")
            with dpg.table(tag="resultsTable"):
                dpg.add_table_column(label="Results")

    # themes/styles bindings
    dpg.bind_font(getGlobalFont())
    dpg.bind_theme(getGlobalTheme())
    dpg.bind_item_theme("errorMessage", getErrorTheme())
    dpg.bind_item_theme("errorMessageQuotas", getErrorTheme())
    dpg.bind_item_theme("window_about", getWindowTheme())
    dpg.bind_item_theme("window_apiQuota", getWindowTheme())
    # dpg.bind_item_theme("errorDialog", getWindowTheme())
    # dpg.bind_item_theme("errorDialogText", getErrorTheme())

    # mouse clicks handler for results table cells
    with dpg.item_handler_registry(tag="cell-handler") as handler:
        dpg.add_item_clicked_handler(callback=cellClicked)

    # keyboard shortcuts
    with dpg.handler_registry():
        # --- for the query text
        # Mac OS | Control
        dpg.add_key_press_handler(341, callback=keyPressCallback)
        # Mac OS | left Command
        dpg.add_key_press_handler(343, callback=keyPressCallback)
        # Mac OS | right Command
        dpg.add_key_press_handler(347, callback=keyPressCallback)
        # Linux | right Ctrl?
        dpg.add_key_press_handler(345, callback=keyPressCallback)
        # Windows | left and right Ctrl
        dpg.add_key_press_handler(17, callback=keyPressCallback)

    # ---

    dpg.create_viewport(
        title="vt-kvd",
        width=1200,
        height=800,
        min_width=windowMinWidth,
        min_height=600
        # small_icon=str(applicationPath/"icons/planet-128.ico"),
        # large_icon=str(applicationPath/"icons/planet-256.ico")
    )

    dpg.setup_dearpygui()
    dpg.show_viewport()
    dpg.set_primary_window(mainWindowID, True)

    #
    # --- things to do on application start
    #
    vtAPIkey = getVirusTotalAPIkeyFromConfig()
    if vtAPIkey is None or not vtAPIkey:
        vtAPIkey = "MISSING-VIRUSTOTAL-API-KEY"
        errorMsg = "Could not find/read a config with VirusTotal API key"
        print(f"[WARNING] {errorMsg}")
        dpg.set_value("errorMessage", errorMsg)
        dpg.show_item("errorMessage")
    else:
        if debugMode:
            print(
                " ".join((
                    "[DEBUG] Got the following VirusTotal API key",
                    f"from config: {vtAPIkey}"
                ))
            )
    if debugMode:
        print(
            " ".join((
                "[DEBUG] Creating VirusTotal client",
                f"with the following agent value: {vtAgent}"
            ))
        )
    vtClient = vt.Client(vtAPIkey, agent=vtAgent)
    if pathToCheck:
        dpg.set_value("input_pathToCheck", pathToCheck)

    dpg.start_dearpygui()

    dpg.destroy_context()


if __name__ == "__main__":
    main()
