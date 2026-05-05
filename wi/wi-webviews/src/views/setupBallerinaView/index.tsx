/**
 * Copyright (c) 2026, WSO2 LLC. (https://www.wso2.com) All Rights Reserved.
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

import { useEffect, useState } from "react";
import styled from "@emotion/styled";
import { Button, Codicon, Icon, ProgressRing } from "@wso2/ui-toolkit";
import { useVisualizerContext } from "../../contexts";
import { DownloadProgress } from "@wso2/wi-core";
import {
    PageBackdrop,
    PageContainer,
    HeaderRow,
    HeaderText,
    HeaderTitle,
    HeaderSubtitle,
    FormPanel,
    FormPanelHeader,
    FormBody,
    FormContent,
} from "../shared/FormPageLayout";

const StepRow = styled.div`
    display: flex;
    align-items: flex-start;
    gap: 12px;
`;

const StepIconWrap = styled.div`
    margin-top: 2px;
    flex-shrink: 0;
    width: 18px;
    display: flex;
    align-items: center;
    justify-content: center;
`;

const StepContent = styled.div`
    display: flex;
    flex-direction: column;
    gap: 2px;
`;

interface StepTitleProps {
    error?: boolean;
}

const StepTitle = styled.span<StepTitleProps>`
    font-size: 13px;
    font-weight: 500;
    color: ${(p: StepTitleProps) => p.error ? "var(--vscode-errorForeground)" : "var(--vscode-foreground)"};
`;

const StepDesc = styled.span`
    font-size: 12px;
    color: var(--vscode-descriptionForeground);
    line-height: 1.5;
`;

const WarningIconWrap = styled.div`
    flex-shrink: 0;
    margin-top: 1px;
    width: 26px;
    height: 26px;
    display: flex;
    align-items: center;
    justify-content: center;
    color: var(--vscode-editorWarning-foreground, #cca700);
`;

const StepContainer = styled.div`
    display: flex;
    flex-direction: column;
    gap: 10px;
    padding: 12px 14px;
    border: 1px solid var(--vscode-widget-border, rgba(128,128,128,0.2));
    border-radius: 6px;
    background: color-mix(in srgb, var(--vscode-editor-background) 60%, transparent);
`;

const SuccessSection = styled.div`
    display: flex;
    flex-direction: column;
    gap: 8px;
    padding: 12px 14px;
    border: 1px solid color-mix(in srgb, var(--vscode-textLink-foreground) 30%, transparent);
    border-radius: 6px;
    background: color-mix(in srgb, var(--vscode-textLink-foreground) 6%, transparent);
`;

const ErrorSection = styled.div`
    display: flex;
    flex-direction: column;
    gap: 8px;
    padding: 12px 14px;
    border: 1px solid color-mix(in srgb, var(--vscode-errorForeground) 30%, transparent);
    border-radius: 6px;
    background: color-mix(in srgb, var(--vscode-errorForeground) 6%, transparent);
`;

const ActionArea = styled.div`
    display: flex;
    flex-direction: column;
    gap: 16px;
    padding-top: 4px;
`;

const STEPS = [
    { title: "Prepare Installation", description: "Checking versions and preparing environment for installation." },
    { title: "Install Ballerina Tool", description: "Downloading and installing the Ballerina tool package." },
    { title: "Install Ballerina Distribution", description: "Downloading and installing the Ballerina distribution package." },
    { title: "Install Java Runtime", description: "Downloading and installing the required Java Runtime Environment." },
    { title: "Complete Setup", description: "Configuring VS Code, setting permissions and finalizing installation." },
];

export function SetupBallerinaView() {
    const { wsClient } = useVisualizerContext();
    const [progress, setProgress] = useState<DownloadProgress | null>(null);
    const [isStarting, setIsStarting] = useState(false);

    useEffect(() => {
        return wsClient.onDownloadProgress((p: DownloadProgress) => setProgress(p));
    }, [wsClient]);

    const handleUpdate = async () => {
        setIsStarting(true);
        setProgress(null);
        try {
            await wsClient.runCommand({ command: "ballerina.setup-ballerina" });
        } catch {
            // Errors surface via onDownloadProgress with step === -1
        } finally {
            setIsStarting(false);
        }
    };

    const handleRestart = () => {
        wsClient.runCommand({ command: "workbench.action.reloadWindow" });
    };

    const getStepIcon = (stepIndex: number) => {
        if (!progress) {
            return <Icon name="radio-button-unchecked" iconSx={{ fontSize: "16px", cursor: "default" }} />;
        }
        const currentStep = progress.step ?? 0;
        const isComplete = progress.success || currentStep > stepIndex;
        const isActive = !progress.success && currentStep === stepIndex;
        if (isComplete) {
            return <Icon name="enable-inverse" iconSx={{ fontSize: "15px", color: "var(--vscode-textLink-foreground)", cursor: "default" }} />;
        }
        if (isActive) {
            return <ProgressRing sx={{ height: "16px", width: "16px" }} />;
        }
        return <Icon name="radio-button-unchecked" iconSx={{ fontSize: "16px", cursor: "default" }} />;
    };

    const getStepTitle = (stepIndex: number, baseTitle: string) => {
        if (!progress) return baseTitle;
        const currentStep = progress.step ?? 0;
        if (!progress.success && currentStep === stepIndex && progress.percentage && progress.totalSize) {
            return `${baseTitle} (${progress.percentage}% - ${progress.totalSize.toFixed(0)}MB)`;
        }
        return baseTitle;
    };

    const isSetupRunning = progress !== null && !progress.success && (progress.step ?? 0) !== -1;

    return (
        <PageBackdrop>
            <PageContainer>
                <FormPanel>
                    <FormPanelHeader>
                        <HeaderRow>
                            <WarningIconWrap>
                                <Codicon name="warning" iconSx={{ fontSize: 22 }} />
                            </WarningIconWrap>
                            <HeaderText>
                                <HeaderTitle variant="h3">Ballerina Setup Required</HeaderTitle>
                                <HeaderSubtitle>
                                    A compatible Ballerina distribution was not found or needs to be updated. Click below to install or update it automatically.
                                </HeaderSubtitle>
                            </HeaderText>
                        </HeaderRow>
                    </FormPanelHeader>

                    <FormBody>
                        <FormContent>
                            <ActionArea>
                                <div>
                                    <Button
                                        appearance="primary"
                                        onClick={handleUpdate}
                                        disabled={isStarting || isSetupRunning}
                                    >
                                        {isStarting ? "Starting…" : "Set Up Ballerina"}
                                    </Button>
                                </div>

                                {progress && (progress.step ?? 0) !== -1 && (
                                    <StepContainer>
                                        {STEPS.map((step, idx) => (
                                            <StepRow key={idx}>
                                                <StepIconWrap>{getStepIcon(idx + 1)}</StepIconWrap>
                                                <StepContent>
                                                    <StepTitle>{getStepTitle(idx + 1, step.title)}</StepTitle>
                                                    <StepDesc>{step.description}</StepDesc>
                                                </StepContent>
                                            </StepRow>
                                        ))}
                                    </StepContainer>
                                )}

                                {progress && progress.step === -1 && (
                                    <ErrorSection>
                                        <StepTitle error>Setup failed</StepTitle>
                                        <StepDesc>{progress.message}</StepDesc>
                                        <StepDesc>Check your internet connection or permissions and try again.</StepDesc>
                                        <div style={{ marginTop: "4px" }}>
                                            <Button appearance="primary" onClick={handleUpdate}>Retry</Button>
                                        </div>
                                    </ErrorSection>
                                )}

                                {progress?.success && (
                                    <SuccessSection>
                                        <StepTitle>Setup complete</StepTitle>
                                        <StepDesc>Restart VS Code to finish applying the changes.</StepDesc>
                                        <div style={{ marginTop: "4px" }}>
                                            <Button appearance="primary" onClick={handleRestart}>Restart VS Code</Button>
                                        </div>
                                    </SuccessSection>
                                )}
                            </ActionArea>
                        </FormContent>
                    </FormBody>
                </FormPanel>
            </PageContainer>
        </PageBackdrop>
    );
}
