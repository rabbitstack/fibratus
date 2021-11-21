<template>
    <el-form ref="form" :model="process" label-width="120px" size="mini">
      <el-form-item label="Name">
        <el-input readonly v-model="process.name">
          <template #append>
            <el-button>
              <ion-icon name="copy-outline"></ion-icon>
            </el-button>
          </template>
        </el-input>
      </el-form-item>
      <el-form-item label="Path">
        <el-input readonly v-model="process.exe">
          <template #append>
            <el-button>
              <ion-icon name="copy-outline"></ion-icon>
            </el-button>
          </template>
        </el-input>
      </el-form-item>
      <el-form-item label="Command line">
        <el-input readonly v-model="process.cmdline">
          <template #append>
            <el-button>
              <ion-icon name="copy-outline"></ion-icon>
            </el-button>
          </template>
        </el-input>
      </el-form-item>
      <el-form-item label="Current directory">
        <el-input readonly v-model="process.cwd">
          <template #append>
            <el-button>
              <ion-icon name="copy-outline"></ion-icon>
            </el-button>
          </template>
        </el-input>
      </el-form-item>
    </el-form>
</template>

<script>
export default {
  name: "General",
  props: {
    ps: Object,
  },
  computed: {
    process() {
      return this.ps
    }
  }
}
</script>
