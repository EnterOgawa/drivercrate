<#
.SYNOPSIS
Runs the packaged DriverCrate scan without downloading or installing a driver.

.DESCRIPTION
Starts DriverCrate hidden, verifies its generated version title, application icons, required
controls, full-width determinate scan progress, device class image list, first-column
ascending/descending sorting, recommended-only filter, current-row non-selection, and bulk
select/clear controls. It also verifies the nine-column TreeTable and its audit/install header, the
Provider source button, its initial enabled count, the default-disabled user-selected-file Provider,
and the local manufacturer/class coverage dialog without exporting its inventory details. It invokes
only read-only scan and display commands and waits for device tree items. It never invokes install.
The output contains aggregate UI state only and does not include device names or identifiers.
#>

[CmdletBinding()]
param(
    [Parameter()]
    [string]$Executable = (Join-Path $PSScriptRoot '..\build\Release\DriverCrate.exe'),

    [Parameter()]
    [ValidateRange(10, 300)]
    [int]$TimeoutSeconds = 90
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$executablePath = [System.IO.Path]::GetFullPath($Executable)
if (!(Test-Path -LiteralPath $executablePath -PathType Leaf)) {
    throw "DriverCrate executable was not found: $executablePath"
}

# 埋込C#の二ABI struct・22fieldと19 PInvokeは、既存Win32 ABIの型とfield順序を保持する。
# callerが自己起動しPID所有を確認したappに対し、三getterは表示問合せ用のremote bufferを割当・書込みする。
# 各getterのfinallyはremote buffer解放とCloseHandleを試みるが、解放APIの成功は保証しない。
# 表示比較はCompareStringExの戻り値が0のときだけordinalへfallbackする。
# TreeViewItem: maskはtext/imageの要求flag、itemはcaller指定のopaque tree item handle、textは対象processのremote buffer addressを運ぶ。
# TreeViewItem.textCapacityはtext要求で2048文字、byte確保はsizeof(char)倍とし、image要求では既定0を運ぶ。imageはReadProcessMemoryItemで読み戻して返す応答fieldで、text getterでは参照しない。
# HeaderItem: maskはheader text要求flag、textは対象processのremote text buffer address、textCapacityは256文字の容量を運ぶ。byte確保はsizeof(char)倍で、読戻し後はbufferの解放を試みる。
# WriteProcessMemoryはTreeViewItem、WriteProcessMemoryHeaderはHeaderItemの要求structをremoteへ書く別ABI宣言である。
# ReadProcessMemoryはremote textをlocal byte配列へ、ReadProcessMemoryItemはremote structをTreeViewItemへ読み戻す。四APIはboolだけを確認し、out transferredのbyte数一致は未検査である。
# GetTreeItemText: PS callerが自己起動PIDの所有を確認してtree/item/PIDを渡す責務を持ち、このpublic getter自体はPID所有を認証しない。
# OpenProcessが0ならWin32Exceptionで確保前に止まり、2048文字のtextか要求structの確保失敗も例外にする。要求書込boolがfalseまたはSendMessageが0なら読戻しへ進まず、読戻しboolがfalseでも文字列を返さない。
# UTF-16のNULがあればそこで切り、なければ固定buffer全体を返す。finallyは部分確保を含む非zero remote bufferとhandleの解放を試みる。
# GetHeaderItemText: PS callerが所有確認した自己起動PIDとheader/column indexを渡し、このpublic getter自体はPID所有を認証しない。indexはmessage引数へ渡し、256文字のtextとHeaderItem要求で照会する。
# OpenProcessが0、片方の確保失敗、書込boolがfalseまたはSendMessageが0、読戻しboolがfalseなら例外にする。NULで切り、なければ固定buffer全体を返す。部分確保もfinallyで解放を試みる。
# GetTreeItemImage: PS callerが所有確認した自己起動PIDとtree/itemを渡し、このpublic getter自体はPID所有を認証しない。remote TreeViewItemへimage要求を置き、応答のimageだけを返す。
# OpenProcessが0またはstruct確保失敗なら後続へ進まず、書込boolがfalseまたはSendMessageが0なら応答を読まず、読戻しboolがfalseでも例外にする。finallyは非zero structとhandleの解放を試みる。
# 三getter共通: 完全な転送byte数、VirtualFreeEx/CloseHandleのboolは未検査であり、cleanup成功は保証しない。SendMessageが0の場合に使うLastErrorの正確性も保証しない。未使用ABI slotと全定数はlayout維持のため残す。
Add-Type @'
using System;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Text;

public static class DriverCrateReadOnlyUiSmokeNative
{
    [StructLayout(LayoutKind.Sequential)]
    private struct TreeViewItem
    {
        public uint mask;
        public IntPtr item;
        public uint state;
        public uint stateMask;
        public IntPtr text;
        public int textCapacity;
        public int image;
        public int selectedImage;
        public int children;
        public IntPtr parameter;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct HeaderItem
    {
        public uint mask;
        public int width;
        public IntPtr text;
        public IntPtr bitmap;
        public int textCapacity;
        public int format;
        public IntPtr parameter;
        public int image;
        public int order;
        public uint type;
        public IntPtr filter;
        public uint state;
    }

    public delegate bool EnumWindowsProc(IntPtr window, IntPtr parameter);

    [DllImport("user32.dll")]
    public static extern bool EnumWindows(EnumWindowsProc callback, IntPtr parameter);

    [DllImport("user32.dll")]
    public static extern uint GetWindowThreadProcessId(IntPtr window, out uint processId);

    [DllImport("user32.dll", CharSet = CharSet.Unicode)]
    public static extern IntPtr GetDlgItem(IntPtr parent, int id);

    [DllImport("user32.dll", CharSet = CharSet.Unicode)]
    public static extern int GetWindowText(IntPtr window, System.Text.StringBuilder text, int count);

    [DllImport("user32.dll")]
    public static extern IntPtr SendMessage(
        IntPtr window, uint message, IntPtr wordParameter, IntPtr longParameter);

    [DllImport("user32.dll")]
    public static extern bool PostMessage(
        IntPtr window, uint message, IntPtr wordParameter, IntPtr longParameter);

    [DllImport("user32.dll")]
    public static extern bool IsWindowEnabled(IntPtr window);

    [DllImport("user32.dll")]
    public static extern bool IsWindowVisible(IntPtr window);

    [DllImport("user32.dll", EntryPoint = "GetClassLongPtrW")]
    public static extern IntPtr GetClassLongPtr(IntPtr window, int index);

    [DllImport("user32.dll", EntryPoint = "GetWindowLongPtrW")]
    public static extern IntPtr GetWindowLongPtr(IntPtr window, int index);

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode)]
    private static extern int CompareStringEx(
        string localeName, uint flags, string left, int leftCount, string right, int rightCount,
        IntPtr version, IntPtr reserved, IntPtr sortHandle);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr OpenProcess(uint access, bool inheritHandle, uint processId);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr VirtualAllocEx(
        IntPtr process, IntPtr address, UIntPtr size, uint allocationType, uint protection);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool VirtualFreeEx(
        IntPtr process, IntPtr address, UIntPtr size, uint freeType);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool WriteProcessMemory(
        IntPtr process, IntPtr address, ref TreeViewItem value, UIntPtr size,
        out UIntPtr bytesWritten);

    [DllImport("kernel32.dll", SetLastError = true, EntryPoint = "WriteProcessMemory")]
    private static extern bool WriteProcessMemoryHeader(
        IntPtr process, IntPtr address, ref HeaderItem value, UIntPtr size,
        out UIntPtr bytesWritten);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool ReadProcessMemory(
        IntPtr process, IntPtr address, [Out] byte[] buffer, UIntPtr size,
        out UIntPtr bytesRead);

    [DllImport("kernel32.dll", SetLastError = true, EntryPoint = "ReadProcessMemory")]
    private static extern bool ReadProcessMemoryItem(
        IntPtr process, IntPtr address, out TreeViewItem buffer, UIntPtr size,
        out UIntPtr bytesRead);

    [DllImport("kernel32.dll")]
    private static extern bool CloseHandle(IntPtr handle);

    public static string GetTreeItemText(IntPtr tree, IntPtr item, uint processId)
    {
        const uint processAccess = 0x0038;
        const uint allocationType = 0x3000;
        const uint pageReadWrite = 0x04;
        const uint memoryRelease = 0x8000;
        const uint treeViewItemText = 0x0001;
        const uint treeViewGetItemWide = 0x113E;
        const int textCapacity = 2048;

        IntPtr process = OpenProcess(processAccess, false, processId);
        if (process == IntPtr.Zero)
        {
            throw new Win32Exception(Marshal.GetLastWin32Error());
        }

        IntPtr remoteText = IntPtr.Zero;
        IntPtr remoteItem = IntPtr.Zero;
        try
        {
            int textBytes = checked(textCapacity * sizeof(char));
            int itemBytes = Marshal.SizeOf(typeof(TreeViewItem));
            remoteText = VirtualAllocEx(process, IntPtr.Zero, (UIntPtr)textBytes,
                                        allocationType, pageReadWrite);
            remoteItem = VirtualAllocEx(process, IntPtr.Zero, (UIntPtr)itemBytes,
                                        allocationType, pageReadWrite);
            if (remoteText == IntPtr.Zero || remoteItem == IntPtr.Zero)
            {
                throw new Win32Exception(Marshal.GetLastWin32Error());
            }

            TreeViewItem request = new TreeViewItem
            {
                mask = treeViewItemText,
                item = item,
                text = remoteText,
                textCapacity = textCapacity
            };
            UIntPtr transferred;
            if (!WriteProcessMemory(process, remoteItem, ref request, (UIntPtr)itemBytes,
                                    out transferred) ||
                SendMessage(tree, treeViewGetItemWide, IntPtr.Zero, remoteItem) == IntPtr.Zero)
            {
                throw new Win32Exception(Marshal.GetLastWin32Error());
            }

            byte[] textBuffer = new byte[textBytes];
            if (!ReadProcessMemory(process, remoteText, textBuffer, (UIntPtr)textBytes,
                                   out transferred))
            {
                throw new Win32Exception(Marshal.GetLastWin32Error());
            }

            string text = Encoding.Unicode.GetString(textBuffer);
            int terminator = text.IndexOf('\0');
            return terminator >= 0 ? text.Substring(0, terminator) : text;
        }
        finally
        {
            if (remoteItem != IntPtr.Zero)
            {
                VirtualFreeEx(process, remoteItem, UIntPtr.Zero, memoryRelease);
            }
            if (remoteText != IntPtr.Zero)
            {
                VirtualFreeEx(process, remoteText, UIntPtr.Zero, memoryRelease);
            }
            CloseHandle(process);
        }
    }

    public static string GetHeaderItemText(IntPtr header, int index, uint processId)
    {
        const uint processAccess = 0x0038;
        const uint allocationType = 0x3000;
        const uint pageReadWrite = 0x04;
        const uint memoryRelease = 0x8000;
        const uint headerItemText = 0x0002;
        const uint headerGetItemWide = 0x120B;
        const int textCapacity = 256;

        IntPtr process = OpenProcess(processAccess, false, processId);
        if (process == IntPtr.Zero)
        {
            throw new Win32Exception(Marshal.GetLastWin32Error());
        }

        IntPtr remoteText = IntPtr.Zero;
        IntPtr remoteItem = IntPtr.Zero;
        try
        {
            int textBytes = checked(textCapacity * sizeof(char));
            int itemBytes = Marshal.SizeOf(typeof(HeaderItem));
            remoteText = VirtualAllocEx(process, IntPtr.Zero, (UIntPtr)textBytes,
                                        allocationType, pageReadWrite);
            remoteItem = VirtualAllocEx(process, IntPtr.Zero, (UIntPtr)itemBytes,
                                        allocationType, pageReadWrite);
            if (remoteText == IntPtr.Zero || remoteItem == IntPtr.Zero)
            {
                throw new Win32Exception(Marshal.GetLastWin32Error());
            }

            HeaderItem request = new HeaderItem
            {
                mask = headerItemText,
                text = remoteText,
                textCapacity = textCapacity
            };
            UIntPtr transferred;
            if (!WriteProcessMemoryHeader(process, remoteItem, ref request, (UIntPtr)itemBytes,
                                          out transferred) ||
                SendMessage(header, headerGetItemWide, (IntPtr)index, remoteItem) == IntPtr.Zero)
            {
                throw new Win32Exception(Marshal.GetLastWin32Error());
            }

            byte[] textBuffer = new byte[textBytes];
            if (!ReadProcessMemory(process, remoteText, textBuffer, (UIntPtr)textBytes,
                                   out transferred))
            {
                throw new Win32Exception(Marshal.GetLastWin32Error());
            }

            string text = Encoding.Unicode.GetString(textBuffer);
            int terminator = text.IndexOf('\0');
            return terminator >= 0 ? text.Substring(0, terminator) : text;
        }
        finally
        {
            if (remoteItem != IntPtr.Zero)
            {
                VirtualFreeEx(process, remoteItem, UIntPtr.Zero, memoryRelease);
            }
            if (remoteText != IntPtr.Zero)
            {
                VirtualFreeEx(process, remoteText, UIntPtr.Zero, memoryRelease);
            }
            CloseHandle(process);
        }
    }

    public static int GetTreeItemImage(IntPtr tree, IntPtr item, uint processId)
    {
        const uint processAccess = 0x0038;
        const uint allocationType = 0x3000;
        const uint pageReadWrite = 0x04;
        const uint memoryRelease = 0x8000;
        const uint treeViewItemImage = 0x0002;
        const uint treeViewGetItemWide = 0x113E;

        IntPtr process = OpenProcess(processAccess, false, processId);
        if (process == IntPtr.Zero)
        {
            throw new Win32Exception(Marshal.GetLastWin32Error());
        }

        IntPtr remoteItem = IntPtr.Zero;
        try
        {
            int itemBytes = Marshal.SizeOf(typeof(TreeViewItem));
            remoteItem = VirtualAllocEx(process, IntPtr.Zero, (UIntPtr)itemBytes,
                                        allocationType, pageReadWrite);
            if (remoteItem == IntPtr.Zero)
            {
                throw new Win32Exception(Marshal.GetLastWin32Error());
            }

            TreeViewItem request = new TreeViewItem
            {
                mask = treeViewItemImage,
                item = item
            };
            UIntPtr transferred;
            if (!WriteProcessMemory(process, remoteItem, ref request, (UIntPtr)itemBytes,
                                    out transferred) ||
                SendMessage(tree, treeViewGetItemWide, IntPtr.Zero, remoteItem) == IntPtr.Zero)
            {
                throw new Win32Exception(Marshal.GetLastWin32Error());
            }

            TreeViewItem response;
            if (!ReadProcessMemoryItem(process, remoteItem, out response, (UIntPtr)itemBytes,
                                       out transferred))
            {
                throw new Win32Exception(Marshal.GetLastWin32Error());
            }
            return response.image;
        }
        finally
        {
            if (remoteItem != IntPtr.Zero)
            {
                VirtualFreeEx(process, remoteItem, UIntPtr.Zero, memoryRelease);
            }
            CloseHandle(process);
        }
    }

    public static int CompareDisplayText(string left, string right)
    {
        const uint comparisonFlags = 0x00000001 | 0x00000008;
        const int stringEqual = 2;
        int result = CompareStringEx(null, comparisonFlags, left, left.Length, right, right.Length,
                                     IntPtr.Zero, IntPtr.Zero, IntPtr.Zero);
        return result == 0 ? String.CompareOrdinal(left, right) : result - stringEqual;
    }
}
'@

Add-Type -AssemblyName UIAutomationClient

$windowMessageCommand = 0x0111
$windowMessageClose = 0x0010
$windowMessageGetIcon = 0x007F
$windowMessageLeftButtonDown = 0x0201
$windowMessageLeftButtonUp = 0x0202
$mouseKeyLeftButton = 0x0001
$buttonGetCheck = 0x00F0
$buttonClick = 0x00F5
$buttonChecked = 1
$iconSmall = 0
$iconBig = 1
$classIcon = -14
$classSmallIcon = -34
$treeViewGetCount = 0x1105
$treeViewGetImageList = 0x1108
$treeViewGetNextItem = 0x110A
$treeViewGetItemState = 0x1127
$headerGetItemCount = 0x1200
$treeViewNextRoot = 0
$treeViewNextSibling = 1
$treeViewNextChild = 4
$treeViewStateImageMask = 0xF000
$windowStyleIndex = -16
$staticTypeMask = 0x001F
$staticOwnerDrawStyle = 0x000D
$scanControlId = 2002
$treeControlId = 2001
$treeHeaderControlId = 2006
$installControlId = 2003
$statusControlId = 2005
$progressControlId = 2004
$recommendedOnlyControlId = 2007
$selectAllControlId = 2008
$clearSelectionControlId = 2009
$providerSourcesControlId = 2010
$localCoverageCommandId = 3100

function Get-CheckedCandidateCount {
    param(
        [Parameter(Mandatory)]
        [IntPtr]$Tree
    )

    [long]$checkedCount = 0
    $classItem = [DriverCrateReadOnlyUiSmokeNative]::SendMessage(
        $Tree, $treeViewGetNextItem, [IntPtr]$treeViewNextRoot, [IntPtr]::Zero)
    # Treeのclass root全件をsiblingが0になるまで辿り、各device配下の選択candidate数だけ合計する。
    while ($classItem -ne [IntPtr]::Zero) {
        $deviceItem = [DriverCrateReadOnlyUiSmokeNative]::SendMessage(
            $Tree, $treeViewGetNextItem, [IntPtr]$treeViewNextChild, $classItem)
        # 各classのdevice childをsiblingが0になるまで辿り、そのdeviceのcandidate状態を集計する。
        while ($deviceItem -ne [IntPtr]::Zero) {
            $candidateItem = [DriverCrateReadOnlyUiSmokeNative]::SendMessage(
                $Tree, $treeViewGetNextItem, [IntPtr]$treeViewNextChild, $deviceItem)
            # 各deviceのcandidateをsiblingが0になるまで辿り、state-image index2だけを選択済みとして数える。
            while ($candidateItem -ne [IntPtr]::Zero) {
                $itemState = [DriverCrateReadOnlyUiSmokeNative]::SendMessage(
                    $Tree, $treeViewGetItemState, $candidateItem,
                    [IntPtr]$treeViewStateImageMask).ToInt64()
                # state-image index2のcandidateだけ選択済み件数へ加え、表示専用や未選択の行を数えない。
                if ((($itemState -band $treeViewStateImageMask) -shr 12) -eq 2) {
                    $checkedCount++
                }
                $candidateItem = [DriverCrateReadOnlyUiSmokeNative]::SendMessage(
                    $Tree, $treeViewGetNextItem, [IntPtr]$treeViewNextSibling, $candidateItem)
            }
            $deviceItem = [DriverCrateReadOnlyUiSmokeNative]::SendMessage(
                $Tree, $treeViewGetNextItem, [IntPtr]$treeViewNextSibling, $deviceItem)
        }
        $classItem = [DriverCrateReadOnlyUiSmokeNative]::SendMessage(
            $Tree, $treeViewGetNextItem, [IntPtr]$treeViewNextSibling, $classItem)
    }
    return $checkedCount
}

$window = [IntPtr]::Zero
$process = Start-Process -FilePath $executablePath -WindowStyle Hidden -PassThru

# 自己起動appの検査全体を囲み、finallyで未終了processへWM_CLOSEを試み15秒後に同PIDだけ停止する。例外時の確実なreapは保証しない。
try {
    $windowDeadline = [DateTime]::UtcNow.AddSeconds(20)
    # UI作成を200msごとに観測し、自己起動PIDのtree付きmain window発見か20秒の期限判定で待機を終える。同期問合せ自体の時間上限は保証しない。
    do {
        Start-Sleep -Milliseconds 200
        $process.Refresh()
        if ($process.HasExited) {
            throw "DriverCrate exited before creating the UI. Exit code: $($process.ExitCode)"
        }

        $processWindows = [System.Collections.Generic.List[IntPtr]]::new()
        $callback = [DriverCrateReadOnlyUiSmokeNative+EnumWindowsProc]{
            param($candidate, $unused)
            [uint32]$ownerProcessId = 0
            [void][DriverCrateReadOnlyUiSmokeNative]::GetWindowThreadProcessId(
                $candidate, [ref]$ownerProcessId)
            # EnumWindowsで得たwindowは自己起動processのPIDと一致したものだけ候補へ残す。
            if ($ownerProcessId -eq [uint32]$process.Id) {
                $processWindows.Add($candidate)
            }
            return $true
        }
        [void][DriverCrateReadOnlyUiSmokeNative]::EnumWindows($callback, [IntPtr]::Zero)

        # Error dialog ではなく、device tree を持つ main window だけを選ぶ。
        foreach ($candidate in $processWindows) {
            if ([DriverCrateReadOnlyUiSmokeNative]::GetDlgItem(
                    $candidate, $treeControlId) -ne [IntPtr]::Zero) {
                $window = $candidate
                break
            }
        }
    } while ($window -eq [IntPtr]::Zero -and [DateTime]::UtcNow -lt $windowDeadline)

    if ($window -eq [IntPtr]::Zero) {
        throw 'DriverCrate main window was not created.'
    }

    $tree = [DriverCrateReadOnlyUiSmokeNative]::GetDlgItem($window, $treeControlId)
    $treeHeader = [DriverCrateReadOnlyUiSmokeNative]::GetDlgItem(
        $window, $treeHeaderControlId)
    $installButton = [DriverCrateReadOnlyUiSmokeNative]::GetDlgItem($window, $installControlId)
    $status = [DriverCrateReadOnlyUiSmokeNative]::GetDlgItem($window, $statusControlId)
    $progress = [DriverCrateReadOnlyUiSmokeNative]::GetDlgItem($window, $progressControlId)
    $recommendedOnlyCheckbox = [DriverCrateReadOnlyUiSmokeNative]::GetDlgItem(
        $window, $recommendedOnlyControlId)
    $selectAllButton = [DriverCrateReadOnlyUiSmokeNative]::GetDlgItem(
        $window, $selectAllControlId)
    $clearSelectionButton = [DriverCrateReadOnlyUiSmokeNative]::GetDlgItem(
        $window, $clearSelectionControlId)
    $providerSourcesButton = [DriverCrateReadOnlyUiSmokeNative]::GetDlgItem(
        $window, $providerSourcesControlId)
    if ($tree -eq [IntPtr]::Zero -or $treeHeader -eq [IntPtr]::Zero -or
        $installButton -eq [IntPtr]::Zero -or $status -eq [IntPtr]::Zero -or
        $recommendedOnlyCheckbox -eq [IntPtr]::Zero -or
        $selectAllButton -eq [IntPtr]::Zero -or $clearSelectionButton -eq [IntPtr]::Zero -or
        $providerSourcesButton -eq [IntPtr]::Zero) {
        throw 'DriverCrate required controls were not created.'
    }

    $providerSourcesCaption = [System.Text.StringBuilder]::new(256)
    [void][DriverCrateReadOnlyUiSmokeNative]::GetWindowText(
        $providerSourcesButton, $providerSourcesCaption, $providerSourcesCaption.Capacity)
    if (!$providerSourcesCaption.ToString().Contains('(9/30)') -or
        ![DriverCrateReadOnlyUiSmokeNative]::IsWindowEnabled($providerSourcesButton)) {
        throw 'DriverCrate Provider source control does not show the expected default sources.'
    }

    if ($progress -ne [IntPtr]::Zero) {
        throw 'DriverCrate still creates the obsolete separate progress control.'
    }
    $statusStyle = [DriverCrateReadOnlyUiSmokeNative]::GetWindowLongPtr(
        $status, $windowStyleIndex).ToInt64()
    if (($statusStyle -band $staticTypeMask) -ne $staticOwnerDrawStyle) {
        throw 'DriverCrate status band is not configured for full-width progress drawing.'
    }

    [long]$treeColumnCount = [DriverCrateReadOnlyUiSmokeNative]::SendMessage(
        $treeHeader, $headerGetItemCount, [IntPtr]::Zero, [IntPtr]::Zero).ToInt64()
    if ($treeColumnCount -ne 9) {
        throw "DriverCrate TreeTable has an unexpected column count: $treeColumnCount"
    }
    $auditColumnTitle = [DriverCrateReadOnlyUiSmokeNative]::GetHeaderItemText(
        $treeHeader, 7, [uint32]$process.Id)
    if ($auditColumnTitle -ne '監査 / 導入') {
        throw "DriverCrate audit/install column is missing: $auditColumnTitle"
    }

    $treeImageList = [DriverCrateReadOnlyUiSmokeNative]::SendMessage(
        $tree, $treeViewGetImageList, [IntPtr]::Zero, [IntPtr]::Zero)
    if ($treeImageList -eq [IntPtr]::Zero) {
        throw 'DriverCrate TreeTable does not have a device class image list.'
    }

    $titleBuffer = [System.Text.StringBuilder]::new(256)
    [void][DriverCrateReadOnlyUiSmokeNative]::GetWindowText(
        $window, $titleBuffer, $titleBuffer.Capacity)
    $productVersion = (Get-Item -LiteralPath $executablePath).VersionInfo.ProductVersion
    $expectedTitle = "DriverCrate $productVersion"
    if ($titleBuffer.ToString() -ne $expectedTitle) {
        throw "Unexpected window title: $($titleBuffer.ToString())"
    }

    $applicationBigIcon = [DriverCrateReadOnlyUiSmokeNative]::SendMessage(
        $window, $windowMessageGetIcon, [IntPtr]$iconBig, [IntPtr]::Zero)
    $applicationSmallIcon = [DriverCrateReadOnlyUiSmokeNative]::SendMessage(
        $window, $windowMessageGetIcon, [IntPtr]$iconSmall, [IntPtr]::Zero)
    # 大iconをwindowから取得できなければclass iconへfallbackして、最後に両sizeの存在を確認する。
    if ($applicationBigIcon -eq [IntPtr]::Zero) {
        $applicationBigIcon = [DriverCrateReadOnlyUiSmokeNative]::GetClassLongPtr(
            $window, $classIcon)
    }
    # 小iconをwindowから取得できなければclass small iconへfallbackし、0のままを成功にしない。
    if ($applicationSmallIcon -eq [IntPtr]::Zero) {
        $applicationSmallIcon = [DriverCrateReadOnlyUiSmokeNative]::GetClassLongPtr(
            $window, $classSmallIcon)
    }
    if ($applicationBigIcon -eq [IntPtr]::Zero -or
        $applicationSmallIcon -eq [IntPtr]::Zero) {
        throw 'DriverCrate top-level window does not have both application icon sizes.'
    }

    # BN_CLICKED の notification code は 0 なので control ID だけを WPARAM に設定する。
    [void][DriverCrateReadOnlyUiSmokeNative]::SendMessage(
        $window, $windowMessageCommand, [IntPtr]$scanControlId, [IntPtr]::Zero)

    $scanDeadline = [DateTime]::UtcNow.AddSeconds($TimeoutSeconds)
    [long]$treeItemCount = 0
    $fullWidthProgressObserved = $false
    $progressSamples = [System.Collections.Generic.List[string]]::new()
    # scanを500msごとに期限まで観測し、tree出現か期限判定で待機を終える。progress表示をsampleし、時間だけで成功にしない。同期問合せ自体の時間上限は保証しない。
    do {
        Start-Sleep -Milliseconds 500
        if ($process.HasExited) {
            throw 'DriverCrate exited during the read-only scan.'
        }
        $treeItemCount = [DriverCrateReadOnlyUiSmokeNative]::SendMessage(
            $tree, $treeViewGetCount, [IntPtr]::Zero, [IntPtr]::Zero).ToInt64()
        $progressStatusBuffer = [System.Text.StringBuilder]::new(2048)
        [void][DriverCrateReadOnlyUiSmokeNative]::GetWindowText(
            $status, $progressStatusBuffer, $progressStatusBuffer.Capacity)
        # progress診断sampleは最初の12件だけ保持し、それ以後の同じ待機で増やさない。
        if ($progressSamples.Count -lt 12) {
            $progressSamples.Add($progressStatusBuffer.ToString())
        }
        $percentageMatch = [regex]::Match(
            $progressStatusBuffer.ToString(), '全体 ([1-9][0-9]?)%')
        if ($percentageMatch.Success) {
            $fullWidthProgressObserved = $true
        }
    } while ($treeItemCount -eq 0 -and [DateTime]::UtcNow -lt $scanDeadline)

    if ($treeItemCount -eq 0) {
        throw 'DriverCrate did not populate the device tree before the timeout.'
    }
    if (!$fullWidthProgressObserved) {
        throw "DriverCrate did not expose an intermediate percentage in the full-width status band. Samples: $($progressSamples -join '; ')"
    }
    $completedStatusBuffer = [System.Text.StringBuilder]::new(2048)
    [void][DriverCrateReadOnlyUiSmokeNative]::GetWindowText(
        $status, $completedStatusBuffer, $completedStatusBuffer.Capacity)
    if ($completedStatusBuffer.ToString().Contains('全体')) {
        throw 'DriverCrate did not restore the status band after scan completion.'
    }

    # 初期状態の第1column昇順を、種類、device、候補の三階層を崩さず確認する。
    $headerClickPoint = [IntPtr](50 -bor (5 -shl 16))
    [long]$classCount = 0
    [long]$deviceCount = 0
    [long]$candidateCount = 0
    [long]$checkedCandidateCount = 0
    [long]$maximumCheckedPerDevice = 0
    [long]$classStateImageCount = 0
    [long]$deviceStateImageCount = 0
    [long]$deviceRowsWithCurrentVersion = 0
    [long]$rowsWithDeviceClassImage = 0
    [long]$recommendedCandidateCount = 0
    [long]$displayOnlyCandidateCount = 0
    [long]$displayOnlyStateImageCount = 0
    [long]$checkedNonRecommendedCount = 0
    $ascendingSortValid = $true
    $class = [DriverCrateReadOnlyUiSmokeNative]::SendMessage(
        $tree, $treeViewGetNextItem, [IntPtr]$treeViewNextRoot, [IntPtr]::Zero)
    while ($class -ne [IntPtr]::Zero) {
        $classCount++
        if ([DriverCrateReadOnlyUiSmokeNative]::GetTreeItemImage(
                $tree, $class, [uint32]$process.Id) -ge 0) {
            $rowsWithDeviceClassImage++
        }
        $classState = [DriverCrateReadOnlyUiSmokeNative]::SendMessage(
            $tree, $treeViewGetItemState, $class, [IntPtr]$treeViewStateImageMask).ToInt64()
        if (($classState -band $treeViewStateImageMask) -ne 0) {
            $classStateImageCount++
        }

        $previousDeviceSortText = $null
        $device = [DriverCrateReadOnlyUiSmokeNative]::SendMessage(
            $tree, $treeViewGetNextItem, [IntPtr]$treeViewNextChild, $class)
        while ($device -ne [IntPtr]::Zero) {
            $deviceCount++
            if ([DriverCrateReadOnlyUiSmokeNative]::GetTreeItemImage(
                    $tree, $device, [uint32]$process.Id) -ge 0) {
                $rowsWithDeviceClassImage++
            }
            $deviceText = [DriverCrateReadOnlyUiSmokeNative]::GetTreeItemText(
                $tree, $device, [uint32]$process.Id)
            $deviceSortText = $deviceText -replace '\s+\|\s+現在:.*$', ''
            if ($null -ne $previousDeviceSortText -and
                [DriverCrateReadOnlyUiSmokeNative]::CompareDisplayText(
                    $previousDeviceSortText, $deviceSortText) -gt 0) {
                $ascendingSortValid = $false
            }
            $previousDeviceSortText = $deviceSortText
            if ($deviceText -match '\| 現在: \S+') {
                $deviceRowsWithCurrentVersion++
            }
            $deviceState = [DriverCrateReadOnlyUiSmokeNative]::SendMessage(
                $tree, $treeViewGetItemState, $device,
                [IntPtr]$treeViewStateImageMask).ToInt64()
            if (($deviceState -band $treeViewStateImageMask) -ne 0) {
                $deviceStateImageCount++
            }

            [long]$checkedForDevice = 0
            $candidate = [DriverCrateReadOnlyUiSmokeNative]::SendMessage(
                $tree, $treeViewGetNextItem, [IntPtr]$treeViewNextChild, $device)
            while ($candidate -ne [IntPtr]::Zero) {
                $candidateCount++
                $candidateText = [DriverCrateReadOnlyUiSmokeNative]::GetTreeItemText(
                    $tree, $candidate, [uint32]$process.Id)
                $isRecommended = $candidateText.StartsWith(
                    '[推奨更新] ', [StringComparison]::Ordinal)
                if ($isRecommended) {
                    $recommendedCandidateCount++
                }
                if ([DriverCrateReadOnlyUiSmokeNative]::GetTreeItemImage(
                        $tree, $candidate, [uint32]$process.Id) -ge 0) {
                    $rowsWithDeviceClassImage++
                }
                $candidateState = [DriverCrateReadOnlyUiSmokeNative]::SendMessage(
                    $tree, $treeViewGetItemState, $candidate,
                    [IntPtr]$treeViewStateImageMask).ToInt64()
                $stateImageIndex = (($candidateState -band $treeViewStateImageMask) -shr 12)
                $isDisplayOnly = $stateImageIndex -eq 0
                if ($isDisplayOnly) {
                    $displayOnlyCandidateCount++
                }
                if ($stateImageIndex -eq 2) {
                    $checkedForDevice++
                    $checkedCandidateCount++
                    if (!$isRecommended) {
                        $checkedNonRecommendedCount++
                    }
                }
                $candidate = [DriverCrateReadOnlyUiSmokeNative]::SendMessage(
                    $tree, $treeViewGetNextItem, [IntPtr]$treeViewNextSibling, $candidate)
            }
            $maximumCheckedPerDevice = [Math]::Max($maximumCheckedPerDevice, $checkedForDevice)
            $device = [DriverCrateReadOnlyUiSmokeNative]::SendMessage(
                $tree, $treeViewGetNextItem, [IntPtr]$treeViewNextSibling, $device)
        }
        $class = [DriverCrateReadOnlyUiSmokeNative]::SendMessage(
            $tree, $treeViewGetNextItem, [IntPtr]$treeViewNextSibling, $class)
    }

    # 初期選択済みcolumnをclickし、降順への切替と三階層のitem数保持を確認する。
    [void][DriverCrateReadOnlyUiSmokeNative]::SendMessage(
        $treeHeader, $windowMessageLeftButtonDown, [IntPtr]$mouseKeyLeftButton, $headerClickPoint)
    [void][DriverCrateReadOnlyUiSmokeNative]::SendMessage(
        $treeHeader, $windowMessageLeftButtonUp, [IntPtr]::Zero, $headerClickPoint)
    $descendingSortValid = $true
    [long]$descendingClassCount = 0
    [long]$descendingDeviceCount = 0
    [long]$descendingCandidateCount = 0
    $class = [DriverCrateReadOnlyUiSmokeNative]::SendMessage(
        $tree, $treeViewGetNextItem, [IntPtr]$treeViewNextRoot, [IntPtr]::Zero)
    while ($class -ne [IntPtr]::Zero) {
        $descendingClassCount++
        $previousDeviceSortText = $null
        $device = [DriverCrateReadOnlyUiSmokeNative]::SendMessage(
            $tree, $treeViewGetNextItem, [IntPtr]$treeViewNextChild, $class)
        while ($device -ne [IntPtr]::Zero) {
            $descendingDeviceCount++
            $deviceText = [DriverCrateReadOnlyUiSmokeNative]::GetTreeItemText(
                $tree, $device, [uint32]$process.Id)
            $deviceSortText = $deviceText -replace '\s+\|\s+現在:.*$', ''
            if ($null -ne $previousDeviceSortText -and
                [DriverCrateReadOnlyUiSmokeNative]::CompareDisplayText(
                    $previousDeviceSortText, $deviceSortText) -lt 0) {
                $descendingSortValid = $false
            }
            $previousDeviceSortText = $deviceSortText
            $candidate = [DriverCrateReadOnlyUiSmokeNative]::SendMessage(
                $tree, $treeViewGetNextItem, [IntPtr]$treeViewNextChild, $device)
            while ($candidate -ne [IntPtr]::Zero) {
                $descendingCandidateCount++
                $candidate = [DriverCrateReadOnlyUiSmokeNative]::SendMessage(
                    $tree, $treeViewGetNextItem, [IntPtr]$treeViewNextSibling, $candidate)
            }
            $device = [DriverCrateReadOnlyUiSmokeNative]::SendMessage(
                $tree, $treeViewGetNextItem, [IntPtr]$treeViewNextSibling, $device)
        }
        $class = [DriverCrateReadOnlyUiSmokeNative]::SendMessage(
            $tree, $treeViewGetNextItem, [IntPtr]$treeViewNextSibling, $class)
    }

    if ($classCount + $deviceCount + $candidateCount -ne $treeItemCount -or
        $classStateImageCount -ne 0 -or $deviceStateImageCount -ne 0 -or
        $maximumCheckedPerDevice -gt 1 -or $deviceRowsWithCurrentVersion -ne $deviceCount -or
        $rowsWithDeviceClassImage -ne $treeItemCount -or !$ascendingSortValid -or
        !$descendingSortValid -or $descendingClassCount -ne $classCount -or
        $descendingDeviceCount -ne $deviceCount -or
        $descendingCandidateCount -ne $candidateCount -or
        $displayOnlyCandidateCount -eq 0 -or $displayOnlyStateImageCount -ne 0 -or
        $checkedNonRecommendedCount -ne 0) {
        throw "DriverCrate device tree, column sort, or one-driver selection invariant is invalid. " +
            "items=$treeItemCount classes=$classCount devices=$deviceCount " +
            "candidates=$candidateCount classStateImages=$classStateImageCount " +
            "deviceStateImages=$deviceStateImageCount maximumChecked=$maximumCheckedPerDevice " +
            "currentDevices=$deviceRowsWithCurrentVersion classImages=$rowsWithDeviceClassImage " +
            "ascending=$ascendingSortValid descending=$descendingSortValid " +
            "descendingClasses=$descendingClassCount descendingDevices=$descendingDeviceCount " +
            "descendingCandidates=$descendingCandidateCount displayOnly=$displayOnlyCandidateCount " +
            "displayOnlyStateImages=$displayOnlyStateImageCount " +
            "checkedNonRecommended=$checkedNonRecommendedCount"
    }

    # 全解除で表示中と保持中の選択が消え、install commandが無効になることを確認する。
    if ([DriverCrateReadOnlyUiSmokeNative]::IsWindowEnabled($clearSelectionButton)) {
        [void][DriverCrateReadOnlyUiSmokeNative]::SendMessage(
            $clearSelectionButton, $buttonClick, [IntPtr]::Zero, [IntPtr]::Zero)
    }
    [long]$clearedCandidateCount = Get-CheckedCandidateCount -Tree $tree
    $bulkClearValid = $clearedCandidateCount -eq 0 -and
        ![DriverCrateReadOnlyUiSmokeNative]::IsWindowEnabled($installButton) -and
        ![DriverCrateReadOnlyUiSmokeNative]::IsWindowEnabled($clearSelectionButton)
    if (!$bulkClearValid) {
        throw 'DriverCrate bulk clear did not remove every install selection.'
    }

    # 推奨更新がある場合は一括選択で初期selectionを復元し、install可能に戻す。
    $bulkSelectValid = $true
    [long]$bulkSelectedCandidateCount = 0
    if ($recommendedCandidateCount -gt 0) {
        if (![DriverCrateReadOnlyUiSmokeNative]::IsWindowEnabled($selectAllButton)) {
            throw 'DriverCrate bulk select is disabled despite recommended updates.'
        }
        [void][DriverCrateReadOnlyUiSmokeNative]::SendMessage(
            $selectAllButton, $buttonClick, [IntPtr]::Zero, [IntPtr]::Zero)
        $bulkSelectedCandidateCount = Get-CheckedCandidateCount -Tree $tree
        $bulkSelectValid = $bulkSelectedCandidateCount -eq $checkedCandidateCount -and
            $bulkSelectedCandidateCount -gt 0 -and
            [DriverCrateReadOnlyUiSmokeNative]::IsWindowEnabled($installButton) -and
            [DriverCrateReadOnlyUiSmokeNative]::IsWindowEnabled($clearSelectionButton)
    }
    elseif ([DriverCrateReadOnlyUiSmokeNative]::IsWindowEnabled($selectAllButton)) {
        $bulkSelectValid = $false
    }
    if (!$bulkSelectValid) {
        throw 'DriverCrate bulk select did not restore the recommended update selection.'
    }

    # Filterを有効にし、install可能な推奨更新以外の候補が表示されないことを確認する。
    [void][DriverCrateReadOnlyUiSmokeNative]::SendMessage(
        $recommendedOnlyCheckbox, $buttonClick, [IntPtr]::Zero, [IntPtr]::Zero)
    $filterCheckState = [DriverCrateReadOnlyUiSmokeNative]::SendMessage(
        $recommendedOnlyCheckbox, $buttonGetCheck, [IntPtr]::Zero, [IntPtr]::Zero).ToInt64()
    [long]$filteredTreeItemCount = [DriverCrateReadOnlyUiSmokeNative]::SendMessage(
        $tree, $treeViewGetCount, [IntPtr]::Zero, [IntPtr]::Zero).ToInt64()
    [long]$filteredClassCount = 0
    [long]$filteredDeviceCount = 0
    [long]$filteredCandidateCount = 0
    $recommendedOnlyFilterValid = $filterCheckState -eq $buttonChecked
    $class = [DriverCrateReadOnlyUiSmokeNative]::SendMessage(
        $tree, $treeViewGetNextItem, [IntPtr]$treeViewNextRoot, [IntPtr]::Zero)
    while ($class -ne [IntPtr]::Zero) {
        $filteredClassCount++
        [long]$filteredDevicesForClass = 0
        $device = [DriverCrateReadOnlyUiSmokeNative]::SendMessage(
            $tree, $treeViewGetNextItem, [IntPtr]$treeViewNextChild, $class)
        while ($device -ne [IntPtr]::Zero) {
            $filteredDevicesForClass++
            $filteredDeviceCount++
            [long]$filteredCandidatesForDevice = 0
            $candidate = [DriverCrateReadOnlyUiSmokeNative]::SendMessage(
                $tree, $treeViewGetNextItem, [IntPtr]$treeViewNextChild, $device)
            while ($candidate -ne [IntPtr]::Zero) {
                $filteredCandidatesForDevice++
                $filteredCandidateCount++
                $candidateText = [DriverCrateReadOnlyUiSmokeNative]::GetTreeItemText(
                    $tree, $candidate, [uint32]$process.Id)
                if (!$candidateText.StartsWith(
                        '[推奨更新] ', [StringComparison]::Ordinal)) {
                    $recommendedOnlyFilterValid = $false
                }
                $candidate = [DriverCrateReadOnlyUiSmokeNative]::SendMessage(
                    $tree, $treeViewGetNextItem, [IntPtr]$treeViewNextSibling, $candidate)
            }
            if ($filteredCandidatesForDevice -eq 0) {
                $recommendedOnlyFilterValid = $false
            }
            $device = [DriverCrateReadOnlyUiSmokeNative]::SendMessage(
                $tree, $treeViewGetNextItem, [IntPtr]$treeViewNextSibling, $device)
        }
        if ($filteredDevicesForClass -eq 0) {
            $recommendedOnlyFilterValid = $false
        }
        $class = [DriverCrateReadOnlyUiSmokeNative]::SendMessage(
            $tree, $treeViewGetNextItem, [IntPtr]$treeViewNextSibling, $class)
    }

    if ($filteredTreeItemCount -ne
            $filteredClassCount + $filteredDeviceCount + $filteredCandidateCount -or
        $filteredCandidateCount -ne $recommendedCandidateCount -or
        !$recommendedOnlyFilterValid) {
        throw 'DriverCrate recommended-only filter returned an invalid candidate set.'
    }

    $filteredStatusBuffer = [System.Text.StringBuilder]::new(2048)
    [void][DriverCrateReadOnlyUiSmokeNative]::GetWindowText(
        $status, $filteredStatusBuffer, $filteredStatusBuffer.Capacity)
    $expectedFilteredStatusPrefix = "$recommendedCandidateCount 件の推奨更新を表示しています。"
    if (!$filteredStatusBuffer.ToString().StartsWith(
            $expectedFilteredStatusPrefix, [StringComparison]::Ordinal)) {
        throw 'DriverCrate recommended-only filter status does not match the visible count.'
    }

    # Filter解除後に元の全候補が復元され、検索結果が失われていないことを確認する。
    [void][DriverCrateReadOnlyUiSmokeNative]::SendMessage(
        $recommendedOnlyCheckbox, $buttonClick, [IntPtr]::Zero, [IntPtr]::Zero)
    [long]$restoredTreeItemCount = [DriverCrateReadOnlyUiSmokeNative]::SendMessage(
        $tree, $treeViewGetCount, [IntPtr]::Zero, [IntPtr]::Zero).ToInt64()
    [long]$restoredCheckedCandidateCount = 0
    $class = [DriverCrateReadOnlyUiSmokeNative]::SendMessage(
        $tree, $treeViewGetNextItem, [IntPtr]$treeViewNextRoot, [IntPtr]::Zero)
    while ($class -ne [IntPtr]::Zero) {
        $device = [DriverCrateReadOnlyUiSmokeNative]::SendMessage(
            $tree, $treeViewGetNextItem, [IntPtr]$treeViewNextChild, $class)
        while ($device -ne [IntPtr]::Zero) {
            $candidate = [DriverCrateReadOnlyUiSmokeNative]::SendMessage(
                $tree, $treeViewGetNextItem, [IntPtr]$treeViewNextChild, $device)
            while ($candidate -ne [IntPtr]::Zero) {
                $candidateState = [DriverCrateReadOnlyUiSmokeNative]::SendMessage(
                    $tree, $treeViewGetItemState, $candidate,
                    [IntPtr]$treeViewStateImageMask).ToInt64()
                if ((($candidateState -band $treeViewStateImageMask) -shr 12) -eq 2) {
                    $restoredCheckedCandidateCount++
                }
                $candidate = [DriverCrateReadOnlyUiSmokeNative]::SendMessage(
                    $tree, $treeViewGetNextItem, [IntPtr]$treeViewNextSibling, $candidate)
            }
            $device = [DriverCrateReadOnlyUiSmokeNative]::SendMessage(
                $tree, $treeViewGetNextItem, [IntPtr]$treeViewNextSibling, $device)
        }
        $class = [DriverCrateReadOnlyUiSmokeNative]::SendMessage(
            $tree, $treeViewGetNextItem, [IntPtr]$treeViewNextSibling, $class)
    }
    $fullTreeRestored = $restoredTreeItemCount -eq $treeItemCount -and
        $restoredCheckedCandidateCount -eq $checkedCandidateCount
    if (!$fullTreeRestored) {
        throw 'DriverCrate did not restore the full candidate tree and selection after filtering.'
    }

    # 端末inventoryの内容を出力せず、local coverage Task Dialogと非保証説明を確認する。
    [void][DriverCrateReadOnlyUiSmokeNative]::PostMessage(
        $window, $windowMessageCommand, [IntPtr]$localCoverageCommandId, [IntPtr]::Zero)
    $coverageDialog = [IntPtr]::Zero
    $coverageTitleFound = $false
    $coverageSummaryFound = $false
    $coverageLimitationFound = $false
    $coverageDialogDeadline = [DateTime]::UtcNow.AddSeconds(10)
    # local coverage dialogを100msごとに観測し、同processの可視windowで三文言を確認できるか10秒の期限判定で待機を終える。各UI問合せ自体の時間上限は保証しない。
    do {
        Start-Sleep -Milliseconds 100
        $coverageWindows = [System.Collections.Generic.List[IntPtr]]::new()
        $coverageWindowCallback = [DriverCrateReadOnlyUiSmokeNative+EnumWindowsProc]{
            param($candidate, $unused)
            [uint32]$ownerProcessId = 0
            [void][DriverCrateReadOnlyUiSmokeNative]::GetWindowThreadProcessId(
                $candidate, [ref]$ownerProcessId)
            # coverage候補は自己起動PIDでmain window以外の可視windowに限り、別processや非表示windowを検査しない。
            if ($ownerProcessId -eq [uint32]$process.Id -and $candidate -ne $window -and
                [DriverCrateReadOnlyUiSmokeNative]::IsWindowVisible($candidate)) {
                $coverageWindows.Add($candidate)
            }
            return $true
        }
        [void][DriverCrateReadOnlyUiSmokeNative]::EnumWindows(
            $coverageWindowCallback, [IntPtr]::Zero)

        # 同processのtooltip等をTask Dialogと誤認しないよう、必要な全表示文を持つwindowを探す。
        foreach ($coverageWindow in $coverageWindows) {
            try {
                $coverageTexts = [System.Collections.Generic.List[string]]::new()
                $coverageRoot = [System.Windows.Automation.AutomationElement]::FromHandle(
                    $coverageWindow)
                $coverageElements = $coverageRoot.FindAll(
                    [System.Windows.Automation.TreeScope]::Descendants,
                    [System.Windows.Automation.Condition]::TrueCondition)
                foreach ($coverageElement in $coverageElements) {
                    $coverageName = $coverageElement.Current.Name
                    if (![String]::IsNullOrEmpty($coverageName)) {
                        $coverageTexts.Add($coverageName)
                    }
                }
                $coverageText = $coverageTexts -join "`n"
                $coverageTitleFound = $coverageText.Contains('ローカル網羅性')
                $coverageSummaryFound = $coverageText.Contains('PnP デバイス')
                $coverageLimitationFound =
                    $coverageText.Contains(
                        '最新・正常・Provider対応・適用可能を意味しません')
                if ($coverageTitleFound -and $coverageSummaryFound -and
                    $coverageLimitationFound) {
                    $coverageDialog = $coverageWindow
                    break
                }
            }
            catch {
                # Dialog構築途中のUI Automation失敗は期限まで再試行する。
            }
        }
    } while ($coverageDialog -eq [IntPtr]::Zero -and
             [DateTime]::UtcNow -lt $coverageDialogDeadline)
    if ($coverageDialog -eq [IntPtr]::Zero) {
        throw "DriverCrate local coverage dialog verification failed. Title: $coverageTitleFound, summary: $coverageSummaryFound, limitation: $coverageLimitationFound"
    }

    $localCoverageDialogValid = $coverageTitleFound -and $coverageSummaryFound -and
        $coverageLimitationFound
    [void][DriverCrateReadOnlyUiSmokeNative]::PostMessage(
        $coverageDialog, $windowMessageClose, [IntPtr]::Zero, [IntPtr]::Zero)

    $statusBuffer = [System.Text.StringBuilder]::new(2048)
    [void][DriverCrateReadOnlyUiSmokeNative]::GetWindowText(
        $status, $statusBuffer, $statusBuffer.Capacity)
    [PSCustomObject]@{
        Title = $titleBuffer.ToString()
        ApplicationIconsAttached = $true
        ProviderSourcesControl = $providerSourcesCaption.ToString()
        LocalCoverageDialogValid = $localCoverageDialogValid
        FullWidthScanProgressObserved = $fullWidthProgressObserved
        TreeItemCount = $treeItemCount
        TreeColumnCount = $treeColumnCount
        AuditColumnTitle = $auditColumnTitle
        DeviceClassImageListAttached = $treeImageList -ne [IntPtr]::Zero
        DeviceClassCount = $classCount
        DeviceCount = $deviceCount
        CandidateCount = $candidateCount
        ParentRowsWithCurrentVersion = $deviceRowsWithCurrentVersion
        RowsWithDeviceClassImage = $rowsWithDeviceClassImage
        FirstColumnAscendingSort = $ascendingSortValid
        FirstColumnDescendingSort = $descendingSortValid
        RecommendedCandidateCount = $recommendedCandidateCount
        DisplayOnlyCandidateCount = $displayOnlyCandidateCount
        DisplayOnlyRowsHaveNoCheck = $displayOnlyStateImageCount -eq 0
        BulkClearValid = $bulkClearValid
        BulkSelectValid = $bulkSelectValid
        BulkSelectedCandidateCount = $bulkSelectedCandidateCount
        RecommendedOnlyFilterValid = $recommendedOnlyFilterValid
        RecommendedFilterStatus = $filteredStatusBuffer.ToString()
        FullTreeRestored = $fullTreeRestored
        CheckedCandidateCount = $checkedCandidateCount
        MaximumCheckedPerDevice = $maximumCheckedPerDevice
        InstallEnabled = [DriverCrateReadOnlyUiSmokeNative]::IsWindowEnabled($installButton)
        Status = $statusBuffer.ToString()
    }
}
finally {
    if (!$process.HasExited) {
        if ($window -ne [IntPtr]::Zero) {
            [void][DriverCrateReadOnlyUiSmokeNative]::PostMessage(
                $window, $windowMessageClose, [IntPtr]::Zero, [IntPtr]::Zero)
        }
        # WM_CLOSE後の終了待機が15秒で終わらない場合だけ、自己起動した一PIDへStop-Processを試みる。追加reap確認は行わない。
        if (!$process.WaitForExit(15000)) {
            # この script が開始した一つの process だけを終了対象にする。
            Stop-Process -Id $process.Id
        }
    }
}
