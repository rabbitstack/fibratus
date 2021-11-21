<template>
  <el-card class="box-card">
    <el-tabs v-model="active">
      <el-tab-pane name="dport" label="Destination Port">
        <el-table
          v-loading="loading"
          header-row-class-name="header-row"
          :data="packets.dport"
          style="width: 100%;"
          height="82vh"
        >

          <el-table-column sortable prop="port" label="PORT" width="280"/>
          <el-table-column sortable prop="count" label="#PACKETS" />
        </el-table>
      </el-tab-pane>

      <el-tab-pane name="sport" label="Source Port"></el-tab-pane>
      <el-tab-pane name="dip" label="Destination IP"></el-tab-pane>
      <el-tab-pane name="sip" label="Source IP"></el-tab-pane>
      <el-tab-pane name="bytes" label="Bytes"></el-tab-pane>
    </el-tabs>
  </el-card>
</template>

<script>
import axios from "axios";
import {ElMessage} from "element-plus";

export default {
  data() {
    return {
      active: 'dport',
      loading: true,
      packets: {}
    }
  },
  methods: {
    getPackets() {
      axios.get(`http://localhost:8081/ingress`)
        .then((res) => {
          this.packets = res.data
          this.loading = false
        })
        .catch((error) => {
          ElMessage.error({showClose: true, message: error, type: 'error'})
          this.loading = false
        })
    }
  },
  created() {
    this.getPackets()
  }
}
</script>
