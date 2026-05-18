import { SettingsPage } from '../components/settings-page'
import type { AuthSettings } from '../types'
import {
  AUTH_DEFAULT_SECTION,
  getAuthSectionContent,
} from './section-registry.tsx'

const defaultAuthSettings: AuthSettings = {
  PasswordLoginEnabled: true,
  PasswordRegisterEnabled: true,
  InviteOnlyRegistrationEnabled: false,
  EmailVerificationEnabled: false,
  RegisterEnabled: true,
  EmailDomainRestrictionEnabled: false,
  EmailAliasRestrictionEnabled: false,
  EmailDomainWhitelist: '',
  invite_code_max_uses_limit: 100,
  invite_code_max_expire_days: 365,
  invite_code_default_max_uses: 1,
  invite_code_default_max_expire_days: 30,
  invite_code_preserve_history_enabled: true,
  invite_code_audit_enabled: false,
  GitHubOAuthEnabled: false,
  GitHubClientId: '',
  GitHubClientSecret: '',
  'discord.enabled': false,
  'discord.client_id': '',
  'discord.client_secret': '',
  'oidc.enabled': false,
  'oidc.client_id': '',
  'oidc.client_secret': '',
  'oidc.well_known': '',
  'oidc.authorization_endpoint': '',
  'oidc.token_endpoint': '',
  'oidc.user_info_endpoint': '',
  TelegramOAuthEnabled: false,
  TelegramBotToken: '',
  TelegramBotName: '',
  LinuxDOOAuthEnabled: false,
  LinuxDOClientId: '',
  LinuxDOClientSecret: '',
  LinuxDOMinimumTrustLevel: '0',
  WeChatAuthEnabled: false,
  WeChatServerAddress: '',
  WeChatServerToken: '',
  WeChatAccountQRCodeImageURL: '',
  TurnstileCheckEnabled: false,
  TurnstileSiteKey: '',
  TurnstileSecretKey: '',
  'passkey.enabled': false,
  'passkey.rp_display_name': '',
  'passkey.rp_id': '',
  'passkey.origins': '',
  'passkey.allow_insecure_origin': false,
  'passkey.user_verification': 'preferred',
  'passkey.attachment_preference': '',
}

export function AuthSettings() {
  return (
    <SettingsPage
      routePath='/_authenticated/system-settings/auth/$section'
      defaultSettings={defaultAuthSettings}
      defaultSection={AUTH_DEFAULT_SECTION}
      getSectionContent={getAuthSectionContent}
    />
  )
}
