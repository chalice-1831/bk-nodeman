<template>
  <section class="monitoring-category">
    <p class="monitoring-category-title">
      <i class="monitoring-category-icon nodeman-icon nc-deploy"></i>
      {{ $t('后台服务器') }}
    </p>
    <div class="monitoring-range">
      <bk-table
        v-if="tableData.length"
        ref="serviceTable"
        class="healthz-table"
        :data="tableData"
        @selection-change="handleSelectionChange">
        <bk-table-column type="selection" width="40" />
        <NmColumn label="IP" prop="ip" />
      </bk-table>
      <ExceptionCard v-else type="notData" :has-border="false"></ExceptionCard>
    </div>
  </section>
</template>

<script lang="ts">
import { Vue, Component, Ref, Watch } from 'vue-property-decorator';
import { ConfigStore } from '@/store/index';
import ExceptionCard from '@/components/exception/exception-card.vue';

@Component({
  name: 'HealthzServiceTable',
  components: {
    ExceptionCard,
  },
})
export default class HealthzServiceTable extends Vue {
  @Ref('serviceTable') private readonly serviceTable!: any;

  private get selectedIps() {
    return ConfigStore.selectedIPs;
  }
  private get tableData() {
    return ConfigStore.allIPs.map(item => ({ ip: item }));
  }

  @Watch('tableData', { deep: true, immediate: true })
  private toggleSelect() {
    this.$nextTick(() => {
      this.toggleSelection(this.tableData);
    });
  }

  public handleSelectionChange(selection: Dictionary[]) {
    ConfigStore.updateSelectedIPs(selection.map(item => item.ip));
  }
  public toggleSelection(rows?: Dictionary[]) {
    if (rows) {
      this.serviceTable.toggleAllSelection(rows);
    } else {
      this.serviceTable.clearSelection();
    }
  }
}
</script>
