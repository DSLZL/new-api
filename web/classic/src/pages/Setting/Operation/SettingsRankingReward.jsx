/*
Copyright (C) 2025 QuantumNous

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU Affero General Public License as
published by the Free Software Foundation, either version 3 of the
License, or (at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
GNU Affero General Public License for more details.

You should have received a copy of the GNU Affero General Public License
along with this program. If not, see <https://www.gnu.org/licenses/>.

For commercial licensing, please contact support@quantumnous.com
*/

import React, { useEffect, useMemo, useRef, useState } from 'react';
import {
  Button,
  Col,
  Form,
  Row,
  Spin,
  Typography,
} from '@douyinfe/semi-ui';
import { IconDelete, IconPlus } from '@douyinfe/semi-icons';
import {
  compareObjects,
  API,
  showError,
  showSuccess,
  showWarning,
} from '../../../helpers';
import { useTranslation } from 'react-i18next';

const LEADERBOARDS = [
  {
    key: 'balance.daily',
    title: '日余额榜',
  },
  {
    key: 'balance.total',
    title: '总余额榜',
  },
  {
    key: 'invites.daily',
    title: '日邀请榜',
  },
  {
    key: 'invites.total',
    title: '总邀请榜',
  },
  {
    key: 'consumption.daily',
    title: '日消耗榜',
  },
  {
    key: 'consumption.total',
    title: '总消耗榜',
  },
];

function createEmptyRulesMap() {
  const empty = {};
  LEADERBOARDS.forEach((item) => {
    empty[item.key] = [];
  });
  return empty;
}

function parseRules(raw) {
  const rulesMap = createEmptyRulesMap();
  if (!raw || typeof raw !== 'string') {
    return rulesMap;
  }
  try {
    const parsed = JSON.parse(raw);
    if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
      return rulesMap;
    }

    LEADERBOARDS.forEach((item) => {
      const rows = parsed[item.key];
      if (!Array.isArray(rows)) return;

      rulesMap[item.key] = rows
        .filter((row) => row && typeof row === 'object' && !Array.isArray(row))
        .map((row) => ({
          rank:
            typeof row.rank === 'number' || typeof row.rank === 'string'
              ? String(row.rank)
              : '',
          quota:
            typeof row.quota === 'number' || typeof row.quota === 'string'
              ? String(row.quota)
              : '',
        }));
    });
  } catch {
    return rulesMap;
  }

  return rulesMap;
}

function serializeRules(rulesMap) {
  const payload = {};
  LEADERBOARDS.forEach((item) => {
    const rows = Array.isArray(rulesMap[item.key]) ? rulesMap[item.key] : [];
    const normalized = rows
      .map((row) => {
        const rank = Number(row.rank);
        const quota = Number(row.quota);
        if (
          !Number.isInteger(rank) ||
          rank <= 0 ||
          !Number.isInteger(quota) ||
          quota < 0
        ) {
          return null;
        }
        return { rank, quota };
      })
      .filter((row) => row !== null)
      .sort((a, b) => a.rank - b.rank);

    if (normalized.length > 0) {
      payload[item.key] = normalized;
    }
  });
  return JSON.stringify(payload);
}

function validateRules(rulesMap) {
  const errors = {};
  LEADERBOARDS.forEach((item) => {
    const seenRank = new Set();
    const rows = Array.isArray(rulesMap[item.key]) ? rulesMap[item.key] : [];
    rows.forEach((row, idx) => {
      const rank = Number(row.rank);
      const quota = Number(row.quota);
      const rankKey = `${item.key}:${idx}:rank`;
      const quotaKey = `${item.key}:${idx}:quota`;

      if (!Number.isInteger(rank) || rank <= 0) {
        errors[rankKey] = '排行榜名次必须为正整数';
      } else if (seenRank.has(rank)) {
        errors[rankKey] = '同一榜单内名次不能重复';
      } else {
        seenRank.add(rank);
      }

      if (!Number.isInteger(quota) || quota < 0) {
        errors[quotaKey] = '奖励额度必须为大于等于 0 的整数';
      }
    });
  });
  return errors;
}

export default function SettingsRankingReward(props) {
  const { t } = useTranslation();
  const [loading, setLoading] = useState(false);
  const [inputs, setInputs] = useState({
    'ranking_reward_setting.enabled': false,
    'ranking_reward_setting.rules': '{}',
  });
  const refForm = useRef();
  const [inputsRow, setInputsRow] = useState(inputs);

  const [rulesMap, setRulesMap] = useState(() => parseRules('{}'));
  const [errors, setErrors] = useState({});

  const enabledValue = inputs['ranking_reward_setting.enabled'];
  const enabled =
    enabledValue === true ||
    enabledValue === 'true' ||
    enabledValue === 1 ||
    enabledValue === '1';
  const ruleJson = useMemo(() => serializeRules(rulesMap), [rulesMap]);

  function handleFieldChange(fieldName) {
    return (value) => {
      setInputs((state) => ({ ...state, [fieldName]: value }));
    };
  }

  function setRuleValue(boardKey, index, field, value) {
    setRulesMap((prev) => {
      const next = { ...prev };
      const rows = [...(next[boardKey] || [])];
      rows[index] = { ...rows[index], [field]: value };
      next[boardKey] = rows;
      return next;
    });
    setErrors({});
  }

  function addRule(boardKey) {
    setRulesMap((prev) => {
      const next = { ...prev };
      const rows = [...(next[boardKey] || [])];
      rows.push({ rank: String(rows.length + 1), quota: '0' });
      next[boardKey] = rows;
      return next;
    });
    setErrors({});
  }

  function removeRule(boardKey, index) {
    setRulesMap((prev) => {
      const next = { ...prev };
      next[boardKey] = (next[boardKey] || []).filter((_, idx) => idx !== index);
      return next;
    });
    setErrors({});
  }

  function onSubmit() {
    const validationErrors = validateRules(rulesMap);
    if (Object.keys(validationErrors).length > 0) {
      setErrors(validationErrors);
      return showWarning(t('请先修正排行榜奖励配置中的错误'));
    }

    const submitInputs = {
      ...inputs,
      'ranking_reward_setting.rules': ruleJson,
    };

    const updateArray = compareObjects(inputsRow, submitInputs);
    if (!updateArray.length) return showWarning(t('你似乎并没有修改什么'));

    const requestQueue = updateArray.map((item) => {
      const value = String(submitInputs[item.key]);
      return API.put('/api/option/', {
        key: item.key,
        value,
      });
    });

    setLoading(true);
    Promise.all(requestQueue)
      .then((res) => {
        if (requestQueue.length === 1) {
          if (res.includes(undefined)) return;
        } else if (requestQueue.length > 1) {
          if (res.includes(undefined))
            return showError(t('部分保存失败，请重试'));
        }
        showSuccess(t('保存成功'));
        props.refresh();
      })
      .catch(() => {
        showError(t('保存失败，请重试'));
      })
      .finally(() => {
        setLoading(false);
      });
  }

  useEffect(() => {
    const currentInputs = {};
    for (let key in props.options) {
      if (Object.keys(inputs).includes(key)) {
        currentInputs[key] = props.options[key];
      }
    }
    if (typeof currentInputs['ranking_reward_setting.enabled'] !== 'boolean') {
      currentInputs['ranking_reward_setting.enabled'] = false;
    }
    if (typeof currentInputs['ranking_reward_setting.rules'] !== 'string') {
      currentInputs['ranking_reward_setting.rules'] = '{}';
    }

    setInputs(currentInputs);
    setInputsRow(structuredClone(currentInputs));
    setRulesMap(parseRules(currentInputs['ranking_reward_setting.rules']));
    setErrors({});
    refForm.current.setValues(currentInputs);
  }, [props.options]);

  return (
    <>
      <Spin spinning={loading}>
        <Form
          values={inputs}
          getFormApi={(formAPI) => (refForm.current = formAPI)}
          style={{ marginBottom: 15 }}
        >
          <Form.Section text={t('排行榜奖励设置')}>
            <Typography.Text
              type='tertiary'
              style={{ marginBottom: 16, display: 'block' }}
            >
              {t('配置排行榜各榜单名次奖励，次日根据昨日快照发放')}
            </Typography.Text>
            <Row gutter={16} style={{ marginBottom: 12 }}>
              <Col xs={24} sm={12} md={8} lg={8} xl={8}>
                <Form.Switch
                  field={'ranking_reward_setting.enabled'}
                  label={t('启用排行榜奖励')}
                  size='default'
                  checkedText='｜'
                  uncheckedText='〇'
                  onChange={handleFieldChange('ranking_reward_setting.enabled')}
                />
              </Col>
            </Row>

            {enabled && (
              <>
                {LEADERBOARDS.map((board) => (
                  <div
                    key={board.key}
                    style={{
                      border: '1px solid var(--semi-color-border)',
                      borderRadius: 8,
                      padding: 12,
                      marginBottom: 12,
                    }}
                  >
                    <Typography.Text strong>{t(board.title)}</Typography.Text>
                    <div style={{ marginTop: 10 }}>
                      {(rulesMap[board.key] || []).map((rule, index) => {
                        const rankError = errors[`${board.key}:${index}:rank`];
                        const quotaError = errors[`${board.key}:${index}:quota`];
                        return (
                          <Row
                            key={`${board.key}-${index}`}
                            gutter={12}
                            style={{ marginBottom: 10 }}
                          >
                            <Col xs={24} sm={10} md={8}>
                              <Form.InputNumber
                                field={`${board.key}.rank.${index}`}
                                label={t('第几名')}
                                min={1}
                                value={rule.rank}
                                onChange={(value) =>
                                  setRuleValue(
                                    board.key,
                                    index,
                                    'rank',
                                    String(value ?? '')
                                  )
                                }
                              />
                              {rankError ? (
                                <Typography.Text type='danger' size='small'>
                                  {t(rankError)}
                                </Typography.Text>
                              ) : null}
                            </Col>
                            <Col xs={24} sm={10} md={8}>
                              <Form.InputNumber
                                field={`${board.key}.quota.${index}`}
                                label={t('奖励额度')}
                                min={0}
                                value={rule.quota}
                                onChange={(value) =>
                                  setRuleValue(
                                    board.key,
                                    index,
                                    'quota',
                                    String(value ?? '')
                                  )
                                }
                              />
                              {quotaError ? (
                                <Typography.Text type='danger' size='small'>
                                  {t(quotaError)}
                                </Typography.Text>
                              ) : null}
                            </Col>
                            <Col xs={24} sm={4} md={4}>
                              <div
                                style={{
                                  display: 'flex',
                                  alignItems: 'flex-end',
                                  height: '100%',
                                }}
                              >
                                <Button
                                  type='danger'
                                  theme='borderless'
                                  icon={<IconDelete />}
                                  onClick={() => removeRule(board.key, index)}
                                />
                              </div>
                            </Col>
                          </Row>
                        );
                      })}
                    </div>
                    <Button
                      icon={<IconPlus />}
                      onClick={() => addRule(board.key)}
                      theme='light'
                    >
                      {t('添加奖励规则')}
                    </Button>
                  </div>
                ))}
              </>
            )}

            <Row>
              <Button size='default' onClick={onSubmit}>
                {t('保存排行榜奖励设置')}
              </Button>
            </Row>
          </Form.Section>
        </Form>
      </Spin>
    </>
  );
}
