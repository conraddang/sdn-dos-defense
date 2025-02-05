import {
  ChakraProvider,
  Box,
  theme,
  GridItem,
  Grid,
} from "@chakra-ui/react";
import { PacketRateChart } from "./PacketRateChart";
import { ControllerInterace } from "./ControllerInterface";

const Page = () => (
  <Box p="5">
    <Grid
      h="200px"
      templateRows="1fr, min-content"
      templateColumns="repeat(2, 1fr)"
      gap={5}
    >
      <GridItem colSpan={1}>
        <Box border="1px" rounded="md" p="4" h="full">
          <ControllerInterace></ControllerInterace>
        </Box>
      </GridItem>
      <GridItem rowSpan={2} colSpan={1}>
        <Box border="1px" rounded="md" p="4">
          <PacketRateChart></PacketRateChart>
        </Box>
      </GridItem>
    </Grid>
  </Box>
);

export const App = () => (
  <ChakraProvider theme={theme}>
    <Page />
  </ChakraProvider>
);
