<template>
  <footer class="footer">
    <p
      class="footer-link"
      v-html="config.i18n.footerInfoHTML"
    ></p>
    <p class="footer-copyright">
      {{ config.footerCopyrightContent }}
    </p>
  </footer>
</template>

<script lang="ts">
import { Vue, Component } from 'vue-property-decorator';
import { PlatformConfigStore } from '@/store/index';

@Component({ name: 'nm-footer' })

export default class NmFooter extends Vue {
  private link: { name: string, href: string, target?: string }[] = [];
  private get config() {
    return PlatformConfigStore.defaults;
  }
  
  private created() {
    this.version =  window.PROJECT_CONFIG.VERSION;
    if (window.PROJECT_CONFIG.BKAPP_RUN_ENV === 'ieod') {
      this.link = [
        {
          name: window.i18n.t('联系BK助手'),
          href: window.PROJECT_CONFIG.BKAPP_NAV_HELPER_URL,
          target: '_blank',
        },
        {
          name: window.i18n.t('蓝鲸桌面'),
          href: window.PROJECT_CONFIG.DESTOP_URL,
          target: '_blank',
        },
      ];
    } else {
      this.link = [
        {
          name: window.i18n.t('技术支持'),
          href: window.PROJECT_CONFIG.BKAPP_NAV_HELPER_URL,
          target: '_blank',
        },
        {
          name: window.i18n.t('社区论坛'),
          href: 'https://bk.tencent.com/s-mart/community/',
          target: '_blank',
        },
        {
          name: window.i18n.t('产品官网'),
          href: 'https://bk.tencent.com/index/',
          target: '_blank',
        },
      ];
    }
  }
}
</script>

<style lang="postcss" scoped>
.footer {
  position: absolute;
  padding: 0 24px;
  bottom: 0;
  left: 50%;
  transform: translateX(-50%);
  width: 100%;
  padding: 19px 0;
  text-align: center;
  /deep/a.link-item {
    color: #3a84ff;
  }
  p {
    line-height: 1;
  }
  &-link {
    margin-bottom: 8px;
    &-list {
      padding: 0 4px;
      &:not(:last-child) {
        border-right: 1px solid #3a84ff;
      }
    }
    &-item {
      display: inline-block;
      color: #3a84ff;
    }
  }
  &-copyright {
    color: #979ba5;
  }
}
</style>
