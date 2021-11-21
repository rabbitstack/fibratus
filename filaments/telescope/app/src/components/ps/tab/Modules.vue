<template>
  <el-table
    row-key="name"
    header-row-class-name="header-row"
    :data="modules"
    style="width: 100%;"
    height="78vh"
  >

    <el-table-column sortable prop="name" label="NAME" width="280"/>
    <el-table-column sortable prop="size" label="SIZE" width="180"/>
    <el-table-column sortable prop="path" label="PATH"/>
  </el-table>
</template>

<script>
export default {
  name: "Modules",
  props: {
    modules: Array,
  }
}
</script>
