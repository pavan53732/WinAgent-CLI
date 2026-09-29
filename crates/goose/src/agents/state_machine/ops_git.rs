//! `/diff` and `/commit` for the state-machine agent loop.
//!
//! The legacy loop's handlers live in `agents/execute_commands.rs`. Both loops
//! call the same `crate::git` entry points so the commit rules — baseline-aware
//! staging, no consumption of unrelated staged work — cannot drift apart.

use anyhow::{anyhow, Result};
use async_trait::async_trait;

use crate::agents::state_machine::{
    messages_since_kickoff, not_applicable, yielded_with, ConversationEffect, Emitter, GooseEffect,
    Operation, OperationResult, SlashCommand,
};
use crate::conversation::message::Message;
use crate::conversation::Conversation;
use crate::session::Session;

pub struct GitCommandOperation;

impl GitCommandOperation {
    pub fn new() -> Self {
        Self
    }
}

#[async_trait]
impl Operation<Session, GooseEffect> for GitCommandOperation {
    fn name(&self) -> &'static str {
        "git_command"
    }

    async fn run_command(
        &self,
        command: &SlashCommand<'_>,
        session: &Session,
        conversation: &Conversation,
        emit: &Emitter,
    ) -> Result<OperationResult<GooseEffect>> {
        let output = match command.command {
            "diff" => Some(run_diff(&session.working_dir, command.params_str).await),
            "commit" => {
                Some(run_commit(&session.working_dir, &session.id, command.params_str).await)
            }
            _ => return not_applicable(),
        };

        let Some(output) = output else {
            return not_applicable();
        };

        let response = Message::assistant()
            .with_text(output)
            .with_visibility(true, false);

        let command_message = messages_since_kickoff(conversation)?
            .first()
            .cloned()
            .ok_or_else(|| anyhow!("git command conversation has no kickoff message"))?;
        let message_id = command_message
            .id
            .clone()
            .ok_or_else(|| anyhow!("persisted slash command message has no id"))?;

        emit.message(command_message.with_visibility(true, false))
            .await;
        let response = emit.message(response).await;

        yielded_with([
            ConversationEffect::SetMessageVisibility {
                message_id,
                user_visible: true,
                agent_visible: false,
            }
            .into(),
            response.into(),
        ])
    }
}

async fn run_diff(repo_dir: &std::path::Path, params_str: &str) -> String {
    let staged = params_str.contains("--staged");
    let file_path = params_str
        .split_whitespace()
        .find(|part| *part != "--staged");
    match crate::git::get_diff(repo_dir, staged, file_path).await {
        Ok(diff) => diff,
        Err(e) => format!("Failed to read git diff: {e}"),
    }
}

async fn run_commit(repo_dir: &std::path::Path, session_id: &str, params_str: &str) -> String {
    let stage_all = params_str.contains("--all");
    let message = params_str.replace("--all", " ").trim().to_string();
    if message.is_empty() {
        return "Usage: /commit <message> commits only the files this session changed.\n\
                /commit --all <message> commits the whole repository, including pre-existing work."
            .to_string();
    }

    match crate::git::commit_for_session(repo_dir, session_id, &message, stage_all).await {
        Ok(output) => output,
        Err(e) => format!("Commit failed: {e}"),
    }
}
