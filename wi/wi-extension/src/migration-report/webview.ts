/**
 * Copyright (c) 2025, WSO2 LLC. (https://www.wso2.com) All Rights Reserved.
 *
 * WSO2 LLC. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

import { Disposable, Uri, ViewColumn, WebviewPanel, window } from "vscode";
import path from "path";
import { ext } from "../extensionVariables";

export class MigrationReportWebview {
    public static currentPanel: MigrationReportWebview | undefined;
    private _panel: WebviewPanel;
    private _disposables: Disposable[] = [];
    private _onOpenSubProjectReport?: (projectName: string) => void;
    private _onGoHome?: () => void;
    /** Scroll-Y to restore once the next page signals it is ready */
    private _pendingScrollY: number = 0;
    /** Scroll-Y of the aggregate report, saved when a sub-project is opened */
    private _aggregateScrollY: number = 0;

    private constructor(
        panel: WebviewPanel,
        reportContent: string,
        showHomeButton: boolean,
        onOpenSubProjectReport?: (projectName: string) => void,
        onGoHome?: () => void
    ) {
        this._panel = panel;
        this._onOpenSubProjectReport = onOpenSubProjectReport;
        this._onGoHome = onGoHome;
        this._panel.onDidDispose(() => this.dispose(), null, this._disposables);

        this._panel.webview.html = this._buildHtml(reportContent, showHomeButton);

        this._panel.webview.onDidReceiveMessage(
            (message) => {
                if (message.type === 'pageReady') {
                    // Page has loaded; send the scroll position now that Chromium is done restoring
                    this._panel.webview.postMessage({ type: 'scrollTo', y: this._pendingScrollY });
                } else if (message.type === 'openSubProjectReport') {
                    if (/^[\w\-]+$/.test(message.projectName)) {
                        // Save aggregate scroll before navigating away
                        this._aggregateScrollY = typeof message.scrollY === 'number' ? message.scrollY : 0;
                        this._onOpenSubProjectReport?.(message.projectName);
                    }
                } else if (message.type === 'goHome') {
                    this._onGoHome?.();
                }
            },
            null,
            this._disposables
        );
    }

    private _buildHtml(reportContent: string, showHomeButton: boolean): string {
        const homeBar = showHomeButton
            ? `<div id="wi-home-bar" style="position:fixed;top:0;left:0;right:0;z-index:9999;display:flex;align-items:center;padding:6px 12px;background:var(--vscode-editor-background,#1e1e1e);border-bottom:1px solid var(--vscode-panel-border,#454545);font-family:var(--vscode-font-family,sans-serif);">
                <button id="wi-home-btn" style="display:flex;align-items:center;gap:6px;padding:4px 12px;cursor:pointer;background:var(--vscode-button-secondaryBackground,#3a3d41);color:var(--vscode-button-secondaryForeground,#ccc);border:1px solid var(--vscode-button-border,transparent);border-radius:3px;font-size:13px;">
                    &#8592; Back to Aggregate Report
                </button>
               </div>
               <div style="height:40px;"></div>`
            : '';

        const withHomeBar = homeBar
            ? reportContent.replace(/(<body[^>]*>)/i, `$1${homeBar}`)
            : reportContent;

        return withHomeBar.replace(
            "</head>",
            `<script>
                (function() {
                    const vscode = acquireVsCodeApi();

                    // Extension will tell us where to scroll once the page is ready
                    window.addEventListener('message', function(event) {
                        if (event.data && event.data.type === 'scrollTo') {
                            window.scrollTo(0, event.data.y || 0);
                        }
                    });

                    document.addEventListener('DOMContentLoaded', function() {
                        // Signal to extension that Chromium has finished loading/restoring scroll
                        vscode.postMessage({ type: 'pageReady' });

                        const defaultStyles = document.getElementById('_defaultStyles');
                        if (defaultStyles) {
                            defaultStyles.remove();
                        }

                        document.querySelectorAll('a.project-link').forEach(function(link) {
                            link.addEventListener('click', function(event) {
                                event.preventDefault();
                                const projectName = link.id || link.textContent.trim();
                                if (/^[\\w\\-]+$/.test(projectName)) {
                                    // Include current scroll position so it can be restored later
                                    vscode.postMessage({ type: 'openSubProjectReport', projectName: projectName, scrollY: window.scrollY });
                                }
                            });
                        });

                        const homeBtn = document.getElementById('wi-home-btn');
                        if (homeBtn) {
                            homeBtn.addEventListener('click', function() {
                                vscode.postMessage({ type: 'goHome' });
                            });
                        }
                    });
                })();
            </script></head>`
        );
    }

    public static createOrShow(
        fileName: string,
        reportContent: string,
        showHomeButton: boolean,
        onOpenSubProjectReport?: (projectName: string) => void,
        onGoHome?: () => void
    ): void {
        if (MigrationReportWebview.currentPanel) {
            MigrationReportWebview.currentPanel._panel.reveal(ViewColumn.Active);
            MigrationReportWebview.currentPanel.updateContent(reportContent, showHomeButton, onOpenSubProjectReport, onGoHome);
            return;
        }

        const panel = window.createWebviewPanel(
            "migrationReport",
            `Migration Report`,
            ViewColumn.Active,
            {
                enableScripts: true,
                retainContextWhenHidden: true,
            }
        );

        panel.iconPath = {
            light: Uri.file(path.join(ext.context.extensionPath, "resources", "icons", "light-icon.svg")),
            dark: Uri.file(path.join(ext.context.extensionPath, "resources", "icons", "dark-icon.svg")),
        };

        MigrationReportWebview.currentPanel = new MigrationReportWebview(panel, reportContent, showHomeButton, onOpenSubProjectReport, onGoHome);
    }

    private updateContent(
        reportContent: string,
        showHomeButton: boolean,
        onOpenSubProjectReport?: (projectName: string) => void,
        onGoHome?: () => void
    ): void {
        this._onOpenSubProjectReport = onOpenSubProjectReport;
        this._onGoHome = onGoHome;
        // Sub-project reports always start at top (0); going back to aggregate restores its saved position
        this._pendingScrollY = showHomeButton ? 0 : this._aggregateScrollY;
        this._panel.webview.html = this._buildHtml(reportContent, showHomeButton);
    }

    public dispose(): void {
        MigrationReportWebview.currentPanel = undefined;
        this._panel.dispose();

        while (this._disposables.length) {
            const disposable = this._disposables.pop();
            if (disposable) {
                disposable.dispose();
            }
        }
    }
}
