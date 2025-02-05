import {
  Text,
  Button,
  Box,
  VStack,
  HStack,
  Divider,
  Heading,
  SimpleGrid,
  Input,
  InputGroup,
  InputRightAddon,
  useBoolean,
  Tag,
} from "@chakra-ui/react";
import { useEffect, useState } from "react";

const styleInactive = { color: "gray" };
const styleActive = { fontWeight: "extrabold" };

const THRESHOLD_DEFAULT = 400;

const postControllerThreshold = (newThreshold: number) => {
  fetch("/threshold", {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
    },
    body: JSON.stringify(newThreshold),
  });
};

export function ControllerInterace() {
  const [defenseActive, setDefenseActive] = useBoolean(true);
  const [activeStage, setActiveStage] = useState<string>("NORMAL");

  useEffect(() => {
    const fetchData = async () => {
      fetch("/controller_stage").then((res) =>
        res.json().then((res) => setActiveStage(res.stage))
      );
    };
    const interval = setInterval(fetchData, 1000);
    return () => clearInterval(interval);
  }, []);

  const b = true;

  return (
    <VStack>
      <Heading size="md">Controller</Heading>
      <Divider />
      <HStack pt={4}>
        <Text>Defense is: </Text>
        <Tag colorScheme={defenseActive ? "orange" : "blue"}>
          {defenseActive ? " active " : "inactive"}
        </Tag>
      </HStack>
      <SimpleGrid columns={2} spacing={10} opacity={defenseActive ? 1 : 0.2}>
        <Text alignSelf={"center"}>Stage</Text>
        <VStack pt="10px" alignItems={"left"}>
          <Text
            {...(defenseActive && activeStage === "NORMAL"
              ? styleActive
              : styleInactive)}
          >
            Normal
          </Text>
          <Text
            {...(defenseActive && activeStage === "MITIGATION"
              ? styleActive
              : styleInactive)}
          >
            Mitigation
          </Text>
          <Text
            {...(defenseActive && activeStage === "BLOCKING"
              ? styleActive
              : styleInactive)}
          >
            Blocking
          </Text>
        </VStack>
      </SimpleGrid>
      <Box pt={10} opacity={defenseActive ? 1 : 0.2}>
        <HStack>
          <Text>DoS detection threshold: </Text>
          <InputGroup width="50%">
            <Input
              defaultValue={THRESHOLD_DEFAULT}
              onChange={(e) => {
                const newThreshold = parseInt(e.target.value);
                postControllerThreshold(newThreshold);
              }}
            />
            <InputRightAddon children="packet rate [1/s]" />
          </InputGroup>
        </HStack>
      </Box>

      <HStack pt={15}>
        <Button
          disabled={defenseActive}
          onClick={() => {
            setDefenseActive.on();
            postControllerThreshold(THRESHOLD_DEFAULT);
            setActiveStage("NORMAL");
          }}
        >
          Activate defense
        </Button>
        <Button
          disabled={!defenseActive}
          onClick={() => {
            setDefenseActive.off();
            // we simulate the disabled defense mechanism by setting the threshold very high
            postControllerThreshold(9999999);
          }}
        >
          Deactive defense
        </Button>
      </HStack>
    </VStack>
  );
}
