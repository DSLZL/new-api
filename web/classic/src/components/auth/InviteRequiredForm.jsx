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

import React, { useEffect, useState } from 'react';
import { useLocation, useNavigate } from 'react-router-dom';
import { useTranslation } from 'react-i18next';
import {
  API,
  getLogo,
  getSystemName,
  setUserData,
  showError,
  showSuccess,
  updateAPI,
} from '../../helpers';
import { Button, Card, Form } from '@douyinfe/semi-ui';
import Title from '@douyinfe/semi-ui/lib/es/typography/title';
import { IconKey } from '@douyinfe/semi-icons';

const InviteRequiredForm = () => {
  const { t } = useTranslation();
  const navigate = useNavigate();
  const location = useLocation();
  const logo = getLogo();
  const systemName = getSystemName();
  const [loading, setLoading] = useState(false);
  const [inviteCode, setInviteCode] = useState('');

  useEffect(() => {
    const params = new URLSearchParams(location.search);
    const aff = (params.get('aff') || '').trim();
    if (!aff) return;
    setInviteCode(aff);
    localStorage.setItem('aff', aff);
  }, [location.search]);

  const handleSubmit = async () => {
    const code = inviteCode.trim();
    if (!code) {
      showError(t('请输入邀请码'));
      return;
    }

    setLoading(true);
    try {
      const res = await API.post('/api/oauth/invite/continue', {
        invite_code: code,
      });
      const { success, message, data } = res.data || {};
      if (!success) {
        const businessCode = data?.code;
        if (businessCode === 'INVITE_CODE_INVALID') {
          showError(t('邀请码无效'));
          return;
        }
        if (businessCode === 'OAUTH_PENDING_EXPIRED') {
          showError(t('OAuth 会话已过期，请重试'));
          navigate('/login');
          return;
        }
        if (businessCode === 'OAUTH_PENDING_NOT_FOUND') {
          showError(t('未找到 OAuth 会话，请重试'));
          navigate('/login');
          return;
        }
        showError(message || t('授权失败'));
        return;
      }

      if (data) {
        localStorage.setItem('user', JSON.stringify(data));
        setUserData(data);
        updateAPI();
      }
      localStorage.setItem('aff', code);
      showSuccess(t('登录成功！'));

      const params = new URLSearchParams(location.search);
      const redirect = params.get('redirect') || '/console/token';
      navigate(redirect);
    } catch (error) {
      showError(error?.message || t('授权失败'));
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className='relative overflow-hidden bg-gray-100 flex items-center justify-center py-12 px-4 sm:px-6 lg:px-8'>
      <div
        className='blur-ball blur-ball-indigo'
        style={{ top: '-80px', right: '-80px', transform: 'none' }}
      />
      <div
        className='blur-ball blur-ball-teal'
        style={{ top: '50%', left: '-120px' }}
      />

      <div className='w-full max-w-sm mt-[60px]'>
        <div className='flex flex-col items-center'>
          <div className='w-full max-w-md'>
            <div className='flex items-center justify-center mb-6 gap-2'>
              <img src={logo} alt='Logo' className='h-10 rounded-full' />
              <Title heading={3} className='!text-gray-800'>
                {systemName}
              </Title>
            </div>

            <Card className='border-0 !rounded-2xl overflow-hidden'>
              <div className='flex justify-center pt-6 pb-2'>
                <Title heading={3} className='text-gray-800 dark:text-gray-200'>
                  {t('注册需要填写邀请码')}
                </Title>
              </div>

              <div className='px-2 py-8'>
                <div className='mb-4 text-center text-sm text-gray-600'>
                  {t('请输入邀请码以完成注册')}
                </div>
                <Form className='space-y-3'>
                  <Form.Input
                    field='invite_code'
                    label={t('邀请码')}
                    placeholder={t('请输入邀请人的 4 位邀请码')}
                    value={inviteCode}
                    onChange={(value) => setInviteCode(value)}
                    prefix={<IconKey />}
                  />

                  <Button
                    theme='solid'
                    className='w-full !rounded-full'
                    type='primary'
                    loading={loading}
                    onClick={handleSubmit}
                  >
                    {t('确认')}
                  </Button>
                </Form>
              </div>
            </Card>
          </div>
        </div>
      </div>
    </div>
  );
};

export default InviteRequiredForm;
